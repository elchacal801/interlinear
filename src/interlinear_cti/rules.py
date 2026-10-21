"""The rule library: YAML rules that gloss known commands deterministically. Rules match defanged text.

Rule regexes run on attacker-written lines, so each one must run in linear time. Four shapes keep it so:
- a rule anchored with {cmd} has a single start, at the start of the text;
- a rule anchored with {stage} also has a single start there, and walks the first line from one simple command to
  the next; every scan after a command start stays inside that command, so no two command starts scan the same text;
- a rule anchored with {anystage} also has a single start there, and walks line by line, each line once, under the
  same scan rule;
- an unanchored rule starts at a literal, such as ">" or "/dev/tcp/", and scans one word after it.
A context rule ({quiet}) also has a single start, and reads the text one command at a time under a grammar with one
reading of every text and bounded repeats (see _QUIET), so a text that fails near its end costs no more than one that
matches.
run_examples() times every rule on long adversarial lines and fails a rule that grows faster than linearly or is
slow even so.

A stored text can hold several lines (an agent's tool call, a zsh multi-line entry, a heredoc). Rules anchored with
{cmd}, {line} or {stage} read only its first line: a later line may be a heredoc body, a quoted string or a note that
only mentions a command, and must not claim the whole text. The high-signal rules still match on any line: a download
piped into or run by a shell, a downloader whose text also writes a crontab or a persistence file ({anystage}), and
the unanchored ones, such as a redirection into authorized_keys or a /dev/tcp shell.

A regex may use these placeholders, which the loader expands before compiling it:
- {cmd}: the command position at the start of the text. That is optional blanks; a case-arm pattern (start),
  *), a|b)); up to 4 group openers: a subshell's (, a brace group's {, or a function header (name() {,
  function name {); then up to 8 of: sudo or doas with their options (-u user, -E, -i), the wrappers nohup,
  busybox, timeout N, env, nice, setsid, time, exec, command -p, stdbuf, sshpass, cmd /c and powershell -c, the
  shell keywords do, then, else, if, elif, while, until and !, and VAR=value assignments, but not to a loader or
  code variable (_LOADERS: LD_PRELOAD=x whoami is left to the model); then an optional path prefix such as
  /usr/bin/, ./, /tmp/ or C:\\Tools\\.
- {line}: the start of the text, and its blanks, without the wrappers.
- {stage}: the same command position at the start of any simple command on the first line: the start of the text,
  after a case-arm pattern there, or after |, ;, &, (, { or a backtick.
- {anystage}: the same at the start of any simple command on any line up to the first line that opens a heredoc
  (<<, but not the here-string <<<), that line included: the start of a line, after a case-arm pattern there, or
  after |, ;, &, (, { or a backtick. The lines after a heredoc opener are its body, a script or a note being
  written, so they are never read. Only for the high-signal rules above.
- {quiet}: a whole text in which every command is context: shell syntax (block keywords, headers whose condition is
  only a test, tests, group openers, case arms), comments, literal assignments, builtins with no effect, plain echo
  and printf, moving around and listing files, apt updates and upgrades (an install goes to the model), and docker
  logs, version and info (listing containers or images is discovery, container-discovery). Nothing that evaluates a
  value as code or arithmetic, or assigns a variable that changes how later commands run, is context (_Q_NEVER,
  _Q_NAME). Its blanks are space and tab only, as bash's are, and it is case-sensitive inside any rule. A context
  rule puts a lookahead for its kind of first command in front of it. The grammar sits behind the gates of
  Library.match: a context rule only ever sees a plainly literal record (plainly_literal) from a transcript unit that
  has not changed how later commands run (changes_later_commands) and holds no control character.
- {pre}: the wrappers and the path prefix alone, for a command after a pipe that the regex matches itself.
- {end}: the end of a command word.
- {word}: one character of a command word: anything but a blank, a shell operator, (, ), {, } or a backtick.
- {seg}: one character of the current simple command, for a scan that must not run into the next one.
"""

from __future__ import annotations

import functools
import math
import re
import time
import warnings
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .iocs import IOC_TYPES, indicators
from .model import Gloss, Technique
from .normalize import has_unusual_characters, is_plain_heredoc_write

CONFIDENCE = ("high", "medium", "low")
MAX_FILE_BYTES = 1 << 20  # a rule file larger than this is refused before YAML reads it
MAX_ITEMS = 200  # the most items a list in a rule may hold, after YAML aliases are expanded
MAX_DEPTH = 64  # the deepest YAML nesting a rule file may use; real files use 3
RULE_ID = r"[a-z0-9][a-z0-9-]{1,63}"


class LibraryError(ValueError):
    """A rule file is malformed or names a technique that is revoked or unknown."""


# The command position. Words never contain a blank, a shell operator, a grouping character or a backtick, so a
# scan over words stops at the end of the simple command it started in. An option's argument never starts with a
# dash, so an option and its argument cannot also be read as two option words: each span has one reading. The
# repeats are bounded (8 wrappers, 16 options each), far above real use, so a long chain costs a bounded amount of
# backtracking and never builds a deep backtracking stack.
_WORD = r"[^\s|;&()<>{}`]"
_WORD_END = r"(?![^\s|;&()<>{}`])"
_BLANKS = r"[^\S\n]+"  # blanks within one line: a newline ends a command, so the prefix never spans lines
# A path prefix ends at a / or \ that a letter follows, since every wrapper and tool name starts with one: in a word
# such as //////..., each place the scan backtracks to then fails at once.
_PATH = r"""(?:[^\s|;&()<>{}`'"]*[/\\](?=[A-Za-z_]))"""
_ARG = _BLANKS + r"[^\s|;&()<>{}`-]" + _WORD + "*"
_OPTIONS = "){0,16}"  # closes an option group
_PS_COMMAND = "c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?"


def _options(letters: str = "", longs: str = "", arg: str = _ARG) -> str:
    """Up to 16 option words of a wrapper, as an alternation that _OPTIONS closes.

    A short option in letters, alone or ending a cluster (-u root, -Eu root), takes the next word as its argument,
    and so does a long option in longs (--user root). Any other dash word is a flag. A dash word that ends in one
    of those letters is never read as a flag, so sudo -u john bash runs bash, never john. The letters match
    case-sensitively even in a (?i) rule, so sudo -H (a flag) is never read as sudo -h host.
    """
    parts, takes = [], []
    if letters:
        letter = "(?-i:[" + letters + "])"
        parts.append(_BLANKS + "-[A-Za-z]*" + letter + arg)
        takes.append("[A-Za-z]*" + letter + _WORD_END)
    if longs:
        parts.append(_BLANKS + "--(?:" + longs + ")" + arg)
        takes.append("-(?:" + longs + ")" + _WORD_END)
    guard = "(?!" + "|".join(takes) + ")" if takes else ""
    parts.append(_BLANKS + "-" + guard + _WORD + "*")
    return "(?:" + "|".join(parts)


# Wrappers that are often run by path (/bin/busybox, C:\Windows\System32\cmd.exe) may take a path prefix; the rest
# may not, and a first-character lookahead skips them all at once when no wrapper can start.
_PATHED = "|".join((
    "busybox",
    r"(?i:cmd)(?:\.exe)?(?:" + _BLANKS + "/[A-Za-z]" + _WORD + r"*){0,8}?" + _BLANKS + "/[CcKk]",
    r"(?i:(?:powershell|pwsh)(?:\.exe)?(?:" + _BLANKS + "-(?!" + _PS_COMMAND + r"\s)[a-z]+(?:" + _ARG + r")?"
    + _OPTIONS + _BLANKS + "-" + _PS_COMMAND + ")",
))
# Long options that take a separate argument are rare in attacker sessions, so only sudo's --user and --group are
# modeled; a glued --option=value is a flag word like any other.
_BARE = "|".join((
    "sudo" + _options("CDghprtTUu", "user|group") + _OPTIONS,
    "doas" + _options("Cu") + _OPTIONS,
    "sshpass" + _options("dfpP") + _OPTIONS,
    "timeout" + _options("ks") + _OPTIONS + _BLANKS + "[0-9]" + _WORD + "*",
    # env with its allowed options only: -i, -0, --, -u NAME and --unset=NAME. Any other option, such as -S or
    # --split-string (which splits its argument into a new command line) or a combined form, leaves the line to the
    # model.
    "env(?:" + _BLANKS + "-[i0-]" + _WORD_END + "|" + _BLANKS + "-u" + _ARG + "|" + _BLANKS + "--unset=" + _WORD
    + "+){0,16}",
    "nice" + _options("n", arg=_BLANKS + "[-+]?[0-9]+") + _OPTIONS,
    "time" + _options("fo") + _OPTIONS,
    "exec" + _options("a") + _OPTIONS,
    "stdbuf" + _options("ioe") + _OPTIONS,
    "setsid" + _options() + _OPTIONS,
    "command(?:" + _BLANKS + "-p){0,4}",
    "nohup", "do", "then", "else", "if", "elif", "while", "until", "!",
))
# Variables whose value is code, names what is loaded or run, or changes how later commands run (the context
# grammar's names below say why each is here). The command position never steps over a VAR=value prefix that names
# one, so LD_PRELOAD=/tmp/x.so whoami or PATH=/tmp/.x id is not described as the command alone: no rule anchored on
# the command claims it, and the line goes to the model. Names are matched case-sensitively, also inside (?i).
_LOADERS = (r"HIST[A-Z_]*|PATH|LD_[A-Z_]+|DYLD_[A-Z_]+|PROMPT_COMMAND|BASH_ENV|ENV|IFS|PS[0-4]|[A-Za-z]+_proxy"
            r"|[A-Z]+_PROXY|PYTHON[A-Z_]*|PERL[A-Z0-9_]*|RUBY[A-Z_]*|NODE_OPTIONS|GIT_[A-Z_]+|SSH_[A-Z_]+|SUDO_[A-Z_]+"
            r"|TMOUT|LESSOPEN|LESSCLOSE|[A-Z_]*PAGER|[A-Z_]*EDITOR|VISUAL|BROWSER|SHELL|GCONV_PATH|NODE_PATH"
            r"|KUBECONFIG|(?=[A-Z_]*JAVA)[A-Z_]*_OPTIONS|APT_CONFIG|LUA_[A-Z0-9_]+|RANDOM|SRANDOM|OPTIND|MAIL|MAILPATH"
            r"|BASH_LOADABLES_PATH|FPATH|TEXTDOMAIN|TEXTDOMAINDIR|ZDOTDIR|HOME|XDG_CONFIG_HOME|OPENSSL_CONF|VIMINIT"
            r"|EXINIT|BASH_XTRACEFD|path|fpath|module_path|mailpath")
# Each [A-Z_]* above backtracks over one name once, so a long name costs linear time; [A-Z_]*JAVA[A-Z_]*_OPTIONS, as
# written before, rescanned the rest of the name from every JAVA in it, which was quadratic on export JAVAJAVA...
_PRE = (r"(?:(?:" + _PATH + r"?(?:" + _PATHED + r")|(?=[bcdeinstuw!])(?:" + _BARE + r"))" + _BLANKS + r"""["']?"""
        + r"|(?!(?-i:" + _LOADERS + r")=)[A-Za-z_][A-Za-z0-9_]*=" + _WORD + "*" + _BLANKS + "){0,8}"
        + _PATH + "?")
# Before the wrappers, a lookahead for a word character: when the scan backtracks into the blanks before a
# command, or meets another operator, it fails at once instead of trying every wrapper again.
_AT_WORD = r"(?=[^\s|;&()<>{}`])"
# The start of the text, the only place an anchored rule looks. The pattern then begins with ^, so the regex engine
# tries that one position only.
_LINE = r"^[^\S\n]*"
def _run(plain: str, special: str) -> str:
    """A non-empty run of plain characters (a character class) and special pieces, unrolled: plain runs are read in
    one step, so a long word is a few steps of the regex engine and not one per character, and each text has one
    reading, since a special piece never starts with a plain character."""
    return ("(?:" + plain + "+(?:(?:" + special + ")" + plain + "*){0,64}|(?:(?:" + special + ")" + plain
            + "*){1,64})")


# What can open a line before its first command. A case-arm pattern (start), *), a|b), start | restart), "stop",
# 'a b')) only at the start
# of a line, where case arms are written: elsewhere x) is the end of a subshell. Then group openers: a subshell's (
# (never the (( of arithmetic), a brace group's { (which a blank follows) and a function header (name() {,
# name(){, function name {, function name() {). At most 4 openers, so the scan stays bounded. These read any
# whitespace as a blank, as the rest of the command position does; the context grammar has its own copies, with
# bash's blanks only (_Q_CASE_ARM, _Q_OPENER). One scan must never mix the two readings: a run of no-break spaces
# that the blanks before a case arm skip and the case-arm word then reads again is quadratic.
_CASE_WORD = _run(r"""[^\s|;&()<>`"']""", r""""[^"\n]*"|'[^'\n]*'""")
_CASE_ARM = _CASE_WORD + r"(?:[^\S\n]*\|[^\S\n]*" + _CASE_WORD + r"){0,16}\)(?=[^\S\n]|$)"
_OPENER = (r"(?:\((?!\()|\{(?=\s|$)"
           r"|(?:function[^\S\n]+)?[A-Za-z_][\w:.-]*[^\S\n]*\(\)[^\S\n]*\{(?=\s|$)"
           r"|function[^\S\n]+[A-Za-z_][\w:.-]*[^\S\n]*\{(?=\s|$))")
_OPENERS = r"(?:" + _CASE_ARM + r"[^\S\n]*)?(?:" + _OPENER + r"[^\S\n]*){0,4}"
# Within one line, lazily to each operator in turn ([^\n] stops at the newline), then the command position. The walk
# itself steps past ( and {, so before it only a case arm needs skipping. The case arm carries its own leading
# blanks: blanks matched before the walk would each, given back one at a time, restart a walk of the whole line.
_WALK = r"(?:[^\S\n]*" + _CASE_ARM + r")?(?:[^\n]*?(?:[|;({`]|(?<![<>])&))??[^\S\n]*" + _AT_WORD + _PRE
# Whole lines skipped lazily from the start of the text, one at a time, but never a line that opens a heredoc (<<):
# the lines after it are the heredoc's body, a script or a note being written rather than commands being run. A
# here-string (<<<) has no body, so it is not an opener. A shift in arithmetic, $((1<<2)), reads as one, which only
# stops the scan early: a known case in the safe direction.
_LINES_BEFORE_A_HEREDOC = r"^(?:(?![^\n]*(?<!<)<<(?!<))[^\n]*\n)*?"


# Context: a text in which every command runs nothing an attack technique describes. A context rule claims a whole
# text or nothing, so it never hides a real command: cd /tmp && ./x is not context, and neither is echo x > file.
# Quoted strings may span lines; $( and backticks are never context, in any position. Neither is a backslash before a
# newline, in or out of double quotes: bash removes it, joining the text around it, so ${x@\<newline>P} is ${x@P}.
# The grammar reads bash's blanks only, space and tab: any other whitespace is part of a word to bash, so a # after a
# no-break space starts no comment (and Library.match leaves a text holding one to the model anyway). It is also
# case-sensitive, even inside a rule written with (?i), so no option letter reads as another (with (?i), declare -n
# passed as a flag); only the command names that navigation matched in any case (CD, DIR, CLS) keep (?i:).
_Q_END = r"(?=[ \t\n|;&()<>]|$)"
_Q_DQ = r'"[^"\\$`]*(?:(?:\\[^\n]|\$(?!\())[^"\\$`]*){0,64}"'
_Q_SQ = r"'[^']*'"
_Q_WORD = _run(r"""[^ \t\n|;&()<>`$"'\\]""", r"\\[^\n]|\$(?!\()|" + _Q_DQ + "|" + _Q_SQ)
# A redirection that writes no file: a copy among descriptors 0 to 2 (>&2, 2>&1) or /dev/null. A higher descriptor
# may be a socket or a file a script opened.
_Q_REDIRECT = r"(?:[0-2]?>&[0-2-](?![0-9])|[0-2&]?>>?[ \t]*/dev/null(?![^ \t\n|;&()<>]))"
# Arguments, never starting with # (a comment, handled after the command).
_Q_ARGS = r"(?:[ \t]+(?!#)(?:" + _Q_REDIRECT + "|" + _Q_WORD + ")){0,128}"
# Variables that change how later commands run or are logged are never context: history, the search paths, the
# loaders (LD_, GCONV_PATH, NODE_PATH, the JVM's options), proxies, interpreters' module paths and startup code
# (LUA_INIT), the prompt, the programs other tools start (pagers, editors, the browser, LESSOPEN and LESSCLOSE, SHELL),
# where docker and kubectl connect, and APT's configuration file (as apt -c, it can set a hook that runs a command).
# So are the names whose value bash or a tool runs, loads or writes to: the integer variables RANDOM, SRANDOM and
# OPTIND, whose every assignment bash evaluates as arithmetic (RANDOM=a\[\$\(id\)\] runs id); MAIL and MAILPATH, whose
# messages an interactive bash expands; BASH_LOADABLES_PATH, FPATH and TEXTDOMAINDIR with TEXTDOMAIN, where builtins,
# functions and translations are loaded from; ZDOTDIR, HOME and XDG_CONFIG_HOME, where shells and tools read their
# startup and configuration files (git and ssh can run commands from theirs); OPENSSL_CONF, which can load a module;
# VIMINIT and EXINIT, editor commands; BASH_XTRACEFD, the descriptor xtrace writes to; and zsh's tied arrays path,
# fpath, module_path and mailpath. Each of these is a name, matched case-sensitively, as bash and zsh match names.
# Credentials are not context either: a name with KEY, TOKEN, SECRET, PASS, PWD, CRED or AUTH in it, or a cloud,
# code-hosting or AI provider's prefix. An exported key is a signal the model should see. Every name that is assigned
# is checked: NAME=value and the names of local, export, declare and the like (_Q_NAME). The names of for and read are
# checked for the code-loading names and the provider prefixes only (_Q_LOADING_NAME): their values come from the list
# or the terminal, not from the text, so read -s password stays context.
_Q_LOADING_NAME = (r"(?!(?:" + _LOADERS + r")(?![A-Za-z0-9_]))"
                   r"(?!(?i:AWS_|AZURE_|GOOGLE_|GCP_|GH_|GITHUB_|OPENAI|ANTHROPIC|HF_|HUGGING|DOCKER_))"
                   r"[A-Za-z_][A-Za-z0-9_]*")
_Q_NAME = r"(?![A-Za-z0-9_]*(?i:KEY|TOKEN|SECRET|PASS|PWD|CRED|AUTH))" + _Q_LOADING_NAME
# A literal value: no $( or backtick, and nothing that names a host. After normalize a host or address carries a [.]
# or [:], a URL has ://, and user@host has an @, so a value with [, @ or :// is not context.
_Q_VALUE = _run(r"""[^ \t\n|;&()<>`$"'\\\[@:]""",
                r""":(?!//)|\\[^\n]|\$(?!\()|"[^"\\$`\[@:]*(?:(?::(?!//)|\\[^\n]|\$(?!\())[^"\\$`\[@:]*){0,64}\""""
                r"""|'[^'\[@:]*(?::(?!//)[^'\[@:]*){0,64}'""")
# An array: values each ending at a blank or the closing ), which may be on a later line.
_Q_ARRAY = r"\((?:[ \t\n]*" + _Q_VALUE + r"(?=[ \t\n)])){0,128}[ \t\n]*\)"
# One assignment. A cheap lookahead for NAME= comes first, so most words skip the long _Q_NAME check. Further
# assignments on the line are prefixes (_Q_PREFIX), so a=1 b=2 has one reading.
_Q_ASSIGN = (r"(?=[A-Za-z_][A-Za-z0-9_]*\+?=)" + _Q_NAME + r"\+?=(?:" + _Q_ARRAY + "|" + _Q_VALUE + ")?" + _Q_END)
# export -f and declare -f (a function), -n (a nameref, which assigns through another name) and -i (an integer, whose
# every later assignment is evaluated as arithmetic, running a subscript that a value holds) are not context, and
# neither is any other option but the attributes -a, -A, -g, -F, -l, -p, -r, -t, -u and -x (not -I, which inherits
# a variable's attributes, an integer's too).
_Q_ASSIGNS = (_Q_ASSIGN + r"|(?:local|export|readonly|declare|typeset)" + _Q_END
              + r"(?:[ \t]+-[aAgFlprtux]+){0,8}"
              r"(?:[ \t]+" + _Q_NAME + r"(?:\+?=(?:" + _Q_ARRAY + "|" + _Q_VALUE + "))?" + _Q_END + "){0,64}")
# Tests: [ ... ] (where < and > would redirect), [[ ... ]] (where &&, ||, <, > and parentheses are part of the
# test) and test. Two kinds of operator evaluate a value as an arithmetic expression, which runs a subscript that the
# value holds (x=a\[\$\(id\)\] stores a[$(id)], and [[ $x -eq 0 ]] then runs id): -eq, -ne, -lt, -le, -gt and -ge in
# [[ ]] (not in [ ] or test, which read plain integers), and -v in all three, which evaluates the subscript of the
# name it is given unless that is a plain name. [ and test read their operators after quote removal, so a quoted,
# escaped, ANSI-C ($'-v') or locale ($"-v") -v counts too; in [[ ]] a quoted operator is a plain word.
_Q_TEST_ARITH = r"-(?:eq|ne|[lg][te])(?![\w-])"
_Q_TEST_V = r"""(?:\$?["']|\\)*-["'\\]*v["']*(?![^ \t\n\]])(?![ \t]+[A-Za-z_][A-Za-z0-9_]*(?=[ \t]|$))"""
# [ and test also split their words after expansion, so an expansion can become an operator: with op=-v, [ $op 'b[x]' ]
# evaluates the subscript of b[x]. Their literal words hold no expansion, but $#, $? and $$, which are always a number,
# and a leading ~/, whose expansion holds a / and so is no operator: no other $, no unquoted glob (* ? [), brace ({)
# or other tilde (~ is HOME and ~- is OLDPWD, either of which can be -v), and no glob that a file named -v matches.
# An expansion is allowed only in one double-quoted word that holds a $ (never "$@" or ${a[@]}, which become several
# words), and only where its value cannot become an operator that reads the word after it: right after a literal
# unary operator other than -v, which takes it as its operand (not -a or -o, which also join two tests); next to a
# literal binary operator, which test reads first, whatever its operands are; or as the only word. With y=-v,
# [ z -a "$y" 'b[x]' ] and [ "$y" 'b[x]' = q ] both run what x holds (checked in bash 5.2 and 5.3).
_Q_TEST_DQ = r'"[^"\\$`]*(?:\\[^\n][^"\\$`]*){0,64}"'  # a double-quoted word with no expansion
_Q_TEST_EXPANSION = (r'"[^"\\$`@]*(?:\\[^\n][^"\\$`@]*){0,64}\$(?![(@])[^"\\$`@]*(?:(?:\\[^\n]|\$(?![(@]))[^"\\$`@]*)'
                     r'{0,64}"' + _Q_END)
_Q_TEST_UNARY = r"-[bcdefghknprstuwxzGLNORS](?=[ \t])"
_Q_TEST_BINARY = r"(?:==?|!=|-(?:eq|ne|lt|le|gt|ge|nt|ot|ef))(?=[ \t])"


def _test_item(literal: str) -> str:
    """One word of [ or test, or an operator with the double-quoted expansion it reads (see _Q_TEST_EXPANSION)."""
    word = "(?!" + _Q_TEST_V + ")" + literal
    return ("(?:" + _Q_TEST_UNARY + r"[ \t]+" + _Q_TEST_EXPANSION
            + "|" + _Q_TEST_EXPANSION + r"[ \t]+" + _Q_TEST_BINARY + r"[ \t]+(?:" + _Q_TEST_EXPANSION + "|" + word + ")"
            + "|" + word + r"[ \t]+" + _Q_TEST_BINARY + r"[ \t]+" + _Q_TEST_EXPANSION + "|" + word + ")")


_Q_TEST_SPECIAL = r"\\[^\n]|\$[#?$]|(?<![^ \t])~/|" + _Q_TEST_DQ + "|" + _Q_SQ
_Q_TEST_BRACKET_ITEM = _test_item(_run(r"""[^ \t\n\]"'`$\\;&|<>()*?\[{~]""", _Q_TEST_SPECIAL))
_Q_TEST_COMMAND_ITEM = _test_item("(?!#)" + _run(r"""[^ \t\n|;&()<>`$"'\\*?\[{~]""", _Q_TEST_SPECIAL))
_Q_TEST = (r"(?:\[\[(?:[ \t]+(?!" + _Q_TEST_ARITH + "|" + _Q_TEST_V + ")"
           + _run(r"""[^ \t\n\]"'`$\\;]""", r"\](?!\])|\\[^\n]|\$(?!\()|" + _Q_DQ + "|" + _Q_SQ)
           + r"){1,64}[ \t]+\]\]|\[(?:(?:[ \t]+" + _Q_TEST_BRACKET_ITEM + r"){1,64}|[ \t]+" + _Q_TEST_EXPANSION
           + r")[ \t]+\]|test" + _Q_END + r"(?:(?:[ \t]+(?:" + _Q_REDIRECT + "|" + _Q_TEST_COMMAND_ITEM + r")){0,128}"
           + r"|[ \t]+" + _Q_TEST_EXPANSION + "))" + _Q_END)
# Headers whose condition is only a test, true, false or :; a for over literal words, whose name is checked as an
# assigned name is; case. An arithmetic for (( )) evaluates its expressions, so it is not context.
_Q_HEADER = (r"(?:(?:if|elif|while|until)[ \t]+(?:![ \t]+)?(?:" + _Q_TEST + "|(?:true|false|:)" + _Q_END + ")"
             r"|for[ \t]+" + _Q_LOADING_NAME + r"(?:[ \t]+in(?:[ \t]+(?!#)" + _Q_WORD + r"){0,64})?" + _Q_END
             + r"|case[ \t]+" + _Q_WORD + r"[ \t]+in" + _Q_END + ")")
# read assigns to the names it is given and to the array that -a names, so each is checked as an assigned name is (a
# name such as a[x] evaluates its subscript). Its options, case-sensitive: the flags e, E, r and s, then at most one
# option that takes an argument, glued to it or as the next word: -a with a name; -d, -i, -n, -N, -p or -t with a
# word; and -u with a descriptor from 0 to 2 (a higher one may be a socket or a file a script opened). Any other option
# is not context. -u is read in the option itself: a lookahead for it, which scanned the rest of the line from every
# read, was quadratic on )read )read ... and stopped at a ; inside quotes, as in read -p "a;b" -u 3 x.
_Q_READ_OPTION = (r"-[eErs]*(?:a(?:" + _Q_LOADING_NAME + "|" + _Q_END + r"[ \t]+" + _Q_LOADING_NAME + r")"
                  r"|[dinNpt](?:" + _Q_WORD + "|" + _Q_END + r"[ \t]+(?!#)" + _Q_WORD + ")"
                  r"|u(?:[0-2]|" + _Q_END + r"[ \t]+[0-2])(?![0-9]))?" + _Q_END)
_Q_READ = (r"read" + _Q_END + r"(?:[ \t]+(?!#)(?:" + _Q_REDIRECT + "|" + _Q_READ_OPTION + "|" + _Q_LOADING_NAME + _Q_END
           + r")){0,64}")
# set: flag clusters that switch shell options and -o with an option's name, all known. -k (keyword) puts every
# NAME=value argument of each later command into that command's environment, so after it ls LD_PRELOAD=/tmp/x.so
# loads the library: -k, a cluster that holds k, -o keyword and any option the grammar does not know are not context.
_Q_SET_FLAGS = "[abefhmnptuvxBCEHPT]"
_Q_SET_NAME = ("(?:allexport|braceexpand|emacs|errexit|errtrace|functrace|hashall|histexpand|history|ignoreeof"
               "|interactive-comments|monitor|noclobber|noexec|noglob|nolog|notify|nounset|onecmd|physical|pipefail"
               "|posix|privileged|verbose|vi|xtrace)")
_Q_BUILTIN = (r"(?:(?:true|false|shift|return|continue|break|wait)(?:[ \t]+[0-9]+)?" + _Q_END
              + r"|:" + _Q_END + _Q_ARGS
              + r"|set(?:[ \t]+(?:-" + _Q_SET_FLAGS + r"*o[ \t]+" + _Q_SET_NAME + "|-" + _Q_SET_FLAGS + r"+|--)"
              + _Q_END + "){1,16}"
              + "|" + _Q_READ + ")")
_Q_NAVIGATION = (r"(?:(?i:cd|pwd|clear|ls|ll|cls|exit|logout)" + _Q_END + _Q_ARGS
                 + r"|(?i:dir)" + _Q_END + r"(?![^\n|;&()]*[ \t]/[sS]" + _Q_END + ")" + _Q_ARGS
                 + r"|(?i:history)(?:[ \t]+[0-9]+)?" + _Q_END + ")")
# printf -v assigns (printf -vNAME too). printf reads its options from its first argument once redirections are set
# aside, after expansion, quote removal and brace, tilde and pathname expansion, so that word may not start with a
# dash or a $, after any quotes or backslashes, and may hold no unquoted {, ~, *, ? or [ (with OLDPWD=-vX, printf ~-
# is printf -vX, and [-]vX or * can match a file named -vX). No later word may start with -v either.
_Q_PRINTF_FIRST = (r"""(?!["'\\]*[-$])""" + _run(r"""[^ \t\n|;&()<>`$"'\\{~*?\[]""",
                                                 r"\\[^\n]|\$(?!\()|" + _Q_DQ + "|" + _Q_SQ) + _Q_END)
_Q_PRINTF = (r"printf" + _Q_END + r"(?:[ \t]+" + _Q_REDIRECT + r"){0,8}(?:[ \t]+(?!#)" + _Q_PRINTF_FIRST
             + r"(?:[ \t]+(?!#)(?:" + _Q_REDIRECT + r"""|(?!["'\\]*-["'\\]*v)""" + _Q_WORD + r")){0,128})?")
_Q_PRINT = r"(?:echo" + _Q_END + _Q_ARGS + "|" + _Q_PRINTF + ")"
# apt updates and upgrades, with flags only. Package names install packages, even after upgrade, and an install is a
# signal the model should see. -o, --option, -c and --config-file can run commands (a Pre-Invoke hook) or read another
# configuration, as APT_CONFIG can (_Q_NAME). Listing and searching packages is software discovery.
_Q_APT_OPTION = r"(?:-[A-Za-bd-np-z]+|--(?!option(?![\w-])|config-file(?![\w-]))[a-z][a-z-]*)" + _Q_END
_Q_PACKAGES = (r"(?:apt|apt-get)(?:[ \t]+" + _Q_APT_OPTION + r"){0,8}[ \t]+(?:update|upgrade|full-upgrade"
               r"|dist-upgrade)" + _Q_END + r"(?:[ \t]+" + _Q_APT_OPTION + r"){0,32}")
# A global option before the subcommand (docker --config DIR, -c CONTEXT, -H HOST) is not context: it can name
# another configuration, context or daemon, and some take the next word, so docker --config info info is not info.
_Q_CONTAINERS = (r"(?:docker[ \t]+(?:compose[ \t]+)?|docker-compose[ \t]+)"
                 r"(?:logs|version|info)" + _Q_END + _Q_ARGS)
_Q_COMMAND = ("(?:" + "|".join((_Q_NAVIGATION, _Q_PRINT, _Q_BUILTIN, _Q_HEADER, _Q_TEST, _Q_PACKAGES, _Q_CONTAINERS,
                                _Q_ASSIGNS, r"(?:fi|done|esac|\})" + _Q_END, r"#[^\n]*(?![^\n])")) + ")")
# The grammar has one reading of every text, so a failure near the end backtracks through each command once
# instead of retrying other splits of the ones before it (Python 3.10 has no atomic groups to force that). Every
# repeat is bounded (256 commands, 128 arguments or array values, 64 test items, special pieces of a word or names),
# so the regex engine's backtracking stack stays small however long the text: a longer text is simply not context,
# and goes to the model. Hence:
# blanks belong to what follows them; a prefix takes the blanks after it only when a command follows; a line that
# starts with a case-arm pattern is read only as a case arm; and a command holds one assignment, the others being
# prefixes; a comment runs to the end of its line, so it never ends before trailing blanks or a ;; that a separator
# could take instead. Before a command: openers, then, do, else and !, sudo with flags that take no argument and run
# the command as it is (-E, -H, -P, -S, -k and -n: -C -D -g -h -p -R -r -T -t -U -u take the next word, so in
# sudo -p ls bash, ls is the prompt and bash runs, and -e, -i, -s and -A run an editor, a shell or a helper), and literal
# assignments (VAR=x cmd). A keyword or opener alone is a whole command too (then, check() {).
_Q_START = r"(?=[^ \t\n;&|)])"  # where a command or prefix can start: not a blank or a separator
# _CASE_ARM and _OPENER with bash's blanks only, as the rest of this grammar reads them.
_Q_CASE_WORD = _run(r"""[^ \t\n|;&()<>`"']""", r""""[^"\n]*"|'[^'\n]*'""")
_Q_CASE_ARM = _Q_CASE_WORD + r"(?:[ \t]*\|[ \t]*" + _Q_CASE_WORD + r"){0,16}\)(?=[ \t]|$)"
_Q_OPENER = (r"(?:\((?!\()|\{(?=[ \t\n]|$)"
             r"|(?:function[ \t]+)?[A-Za-z_][\w:.-]*[ \t]*\(\)[ \t]*\{(?=[ \t\n]|$)"
             r"|function[ \t]+[A-Za-z_][\w:.-]*[ \t]*\{(?=[ \t\n]|$))")
_Q_PREFIX = (r"(?:" + _Q_OPENER + r"|(?:then|do|else)(?=[ \t\n;]|$)|!(?=[ \t])|sudo(?:[ \t]+-[EHPSkn]+){0,8}(?=[ \t])"
             + "|" + _Q_ASSIGN + r"(?=[ \t]+[^ \t\n;&|)#]))(?:[ \t]+(?=[^ \t\n;&|)#]))?")
_Q_BODY = r"(?:" + _Q_PREFIX + r"){0,4}(?:" + _Q_COMMAND + r")?(?:[ \t]+#[^\n]*(?![^\n]))?"
_Q_SEGMENT = r"(?:[ \t]*" + _Q_START + _Q_BODY + ")?"
_Q_LINE_SEGMENT = (r"(?:[ \t]*" + _Q_START + r"(?:" + _Q_CASE_ARM + r"(?:[ \t]+(?=[^ \t\n;&|)#]))?|(?!" + _Q_CASE_ARM
                   + "))" + _Q_BODY + ")?")
# Commands are separated by ;, &&, || and ) on a line, and by newlines and ;; (which start a line, where a case arm
# may come). A ; never runs into a ;;, so each separator has one reading.
# Never context, anywhere in the text, quoted or not (single quotes keep these literal, but a later eval or ${x@P}
# runs them, and the scan stays one literal test per place):
# - $( or a backtick;
# - @P}, the end of ${x@P}, which expands a value as a prompt and so runs what it holds;
# - what evaluates a value as an arithmetic expression, which runs a subscript the value holds: $[ ], ${!x}
#   (indirection; ${!a[@]} and ${!prefix*} list names and evaluate nothing), an offset ${x:n}, and a subscript ${a[x]}
#   other than [@], [*] or a plain number;
# - ${x=v} and ${x:=v}, which assign without NAME=value, so _Q_NAME never sees the name.
# Each test starts at a literal ($, ` or @) and reads at most one name after it, and names never overlap, so the scan
# is linear (a ${ followed by any text up to an @P would rescan the rest of the line from every ${).
_Q_PARAM = r"(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*])"
_Q_INDEX = r"(?:[@*]|[0-9]+)\]"  # after a [, a subscript that evaluates nothing
_Q_NEVER = (r"\$\(|`|@P\}|\$\[|\$\{(?:!(?![A-Za-z_][A-Za-z0-9_]*(?:\[[@*]\]|[@*])\})|#?" + _Q_PARAM
            + r"(?:\[(?!" + _Q_INDEX + r")|(?:\[" + _Q_INDEX + r")?(?::(?![-+?])|=)))")
_QUIET = (r"(?-i:^(?![\s\S]*?(?:" + _Q_NEVER + r"))[ \t]*(?=[^ \t\n])" + _Q_LINE_SEGMENT + r"(?:[ \t]*(?:\n|;;)"
          + _Q_LINE_SEGMENT + r"|[ \t]*(?:;(?!;)|&&|\|\||\))" + _Q_SEGMENT + r"){0,256}[ \t]*\Z)")
PLACEHOLDERS = {
    "word": _WORD,
    "line": _LINE,
    "pre": _AT_WORD + _PRE,
    "cmd": _LINE + _OPENERS + _AT_WORD + _PRE,
    "stage": "^" + _WALK,
    "anystage": _LINES_BEFORE_A_HEREDOC + _WALK,
    "quiet": _QUIET,
    "end": r"""(?=[\s|;&()<>{}`'"]|$)""",
    "seg": r"(?:[^|;&(){}`\n]|(?<=[<>])&)",
}
_PLACEHOLDER = re.compile(r"\{([a-z]+)\}")


def expand(pattern: str) -> str:
    """pattern with its placeholders replaced. An unknown {name} is an error, so a misspelled one is not a literal."""
    unknown = sorted({m.group(1) for m in _PLACEHOLDER.finditer(pattern)} - set(PLACEHOLDERS))
    if unknown:
        raise LibraryError(f"unknown placeholder {{{unknown[0]}}}")
    return _PLACEHOLDER.sub(lambda m: PLACEHOLDERS[m.group(1)], pattern)


# CONTEXT is an allowlist. Before any context rule may claim a record, the record must be plainly literal
# (plainly_literal), its transcript unit must hold no control character (parse, Source.no_context), and no earlier
# record of that unit may change how later commands resolve or run (changes_later_commands). Anything else is left
# to the rules that name a technique, or to the model: the safe direction, which costs model calls, never a hidden
# command. The grammar behind {quiet} still reads every literal record.
_PRINTABLE = re.compile(r"[\t\x20-\x7e]*", re.ASCII)  # one line of printable ASCII, space and tab
_NOT_LITERAL = frozenset("$\\(){}<>|&;!*?[]`")
# zsh's special parameters with lowercase names: each changes how zsh finds or runs commands, or what it prints.
_ZSH_SPECIAL = frozenset(("path", "fpath", "cdpath", "manpath", "module_path", "mailpath", "functions", "aliases",
                          "galiases", "saliases", "commands", "options", "parameters", "prompt", "psvar"))
_LOCAL_NAME = re.compile(r"[a-z][a-z0-9_]*", re.ASCII)
_ASSIGNED = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?=(?:\[[^\]]*\])?\+?=)", re.ASCII)  # NAME= at a word's start
# zsh reads these numbers as arithmetic, which runs a subscript that a variable's value holds (x=a\[\$\(id\)\], then
# exit x): the arguments of exit, logout, return, shift, break and continue, read's -t, -n, -N, -u and -k, and printf's
# arguments for a numeric conversion. In a literal record they are digits.
_MATH_ARGS = frozenset(("exit", "logout", "return", "shift", "break", "continue"))
_NUMERIC_CONVERSION = re.compile(r"%[-+ #0-9.]*[diouxXeEfFgGaAc]", re.ASCII)
_NUMBER = re.compile(r"[-+]?[0-9]+(?:\.[0-9]+)?", re.ASCII)
_KEYWORDS = frozenset(("then", "do", "else", "elif", "if", "while", "until"))


def _plain_numbers(words: list[str]) -> bool:
    """Whether every number that zsh would read as arithmetic in these words is digits (see _MATH_ARGS)."""
    start = next((i for i, word in enumerate(words) if word not in _KEYWORDS), len(words))
    command, args = (words[start], words[start + 1:]) if start < len(words) else ("", [])
    if command in _MATH_ARGS:
        return all(word.isdigit() for word in args)
    if command == "printf" and args and _NUMERIC_CONVERSION.search(" ".join(args)):
        return all(_NUMBER.fullmatch(word.strip("'\"")) for word in args[1:])
    if command == "read":
        number = False  # the next word is an option's number
        for word in args:
            if number:
                if not word.isdigit():
                    return False
                number = False
            elif word.startswith("-"):
                at = next((i for i, ch in enumerate(word) if ch in "tnNuk"), None)
                if at is not None:
                    rest = word[at + 1:]
                    if rest and not rest.isdigit():
                        return False
                    number = not rest
        return not number
    return True


def plainly_literal(text: str, zsh: bool = False) -> bool:
    """Whether text is plainly literal, the only kind of record a context rule may claim.

    That is one line of printable ASCII, space and tab with none of $ \\ ( ) { } < > | & ; ! * ? [ ] or a backtick,
    and no ~ but a leading ~/ in a word. Quotes are allowed when they are balanced, since the quoted text passes the
    same test. An assignment word (name=value) needs a name of lowercase letters, digits and _ that is not one of
    zsh's special parameters, and is never literal in a zsh history (zsh_history). A number that zsh reads as
    arithmetic is digits (_MATH_ARGS). Two exceptions: a whole-line
    comment (its first non-blank character is #) may hold any printable ASCII, and the test form [ words ] may use
    [ and ] as its first and last words. Linear: each character is looked at once.
    """
    if _PRINTABLE.fullmatch(text) is None:
        return False
    body = text.strip(" \t")
    if body.startswith("#"):
        return True
    words = body.split()
    if len(words) >= 2 and words[0] == "[" and words[-1] == "]":
        words = words[1:-1]
    for word in words:
        assigned = _ASSIGNED.match(word)
        if assigned and (zsh or not _LOCAL_NAME.fullmatch(assigned.group()) or assigned.group() in _ZSH_SPECIAL):
            return False
    if not _plain_numbers(words):
        return False
    quote = ""
    previous = " "
    line = " ".join(words)
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        if ch in _NOT_LITERAL or (ch == "~" and not (previous == " " and line[i + 1:i + 2] == "/")):
            return False
        previous = ch
    return not quote


# Records that can change how later commands resolve or run (session taint). Once one of these is in a transcript
# unit (a history file, a script or an agent log), no record from it on is labeled context. Every test reads the
# text with its quotes and backslashes removed, as bash reads a command word (a''lias and \alias are alias), and
# over-matches on purpose: alias in an argument also taints, which costs model calls only.
_TAINT_WORDS = ("alias", "unalias", "hash", "enable", "disable", "set", "setopt", "unsetopt", "shopt", "emulate",
                "trap", "source", "eval", "exec", "builtin", "function", "functions", "autoload", "zmodload",
                "unfunction", "bind", "bindkey", "zle", "complete", "compdef", "integer", "float", "add-zsh-hook")
_TAINT = re.compile(
    r"(?<![\w.-])(?P<word>" + "|".join(_TAINT_WORDS) + r")(?![\w-])"
    r"|(?<![^\s;&|(){}`!])(?P<dot>\.)(?=[ \t])"  # . file
    r"|(?P<function>\([ \t]*\))"  # name() or an anonymous () {
    r"|(?P<array>=\()"  # an array assignment, = or +=, such as BASH_CMDS=(ls /tmp/x) or precmd_functions+=(x)
    r"|(?<![\w-])(?P<option>export|declare|typeset|local|readonly)[ \t]+[-+]"  # with any option
    r"|(?<![\w-])(?P<command>command)[ \t]+-[A-Za-z]*p"
    r"|(?P<loader>PATH|LD_|PRELOAD)"
    # PowerShell's aliases, functions, modules and profile
    r"|(?i:(?<![\w-])(?P<powershell>set-alias|new-alias|sal|nal|import-module|ipmo|add-type|invoke-expression|iex"
    r"|set-item|si)(?![\w-])|(?P<drive>\$profile|(?:function|alias):))"
    # a shell's or readline's startup file, APT's configuration and the dynamic loader's
    r"|(?P<startup>\.(?:bashrc|bash_profile|bash_login|bash_aliases|profile|zshrc|zshenv|zprofile|zlogin|inputrc)"
    r"|/etc/(?:profile|bash|zsh|environment)|apt\.conf|ld\.so)",
    re.ASCII)
_TAINT_REASONS = {"word": None, "dot": "the . builtin", "function": "a function definition",
                  "array": "an array assignment", "option": "an option to {}", "command": "command -p",
                  "loader": "a search path or loader variable",
                  "powershell": "Invoke-Expression or a PowerShell alias, module or type",
                  "drive": "a PowerShell profile, function or alias", "startup": "a startup or configuration file"}
# What may come before a command word: keywords, precommand modifiers and their options, redirections, prefix
# assignments.
_BEFORE_COMMAND = frozenset(("if", "then", "do", "else", "elif", "while", "until", "time", "!", "coproc", "command",
                             "builtin", "exec", "noglob", "nocorrect", "-"))
_REDIRECTION = re.compile(r"[0-9]*(?:[<>]|&>)[<>&|-]*", re.ASCII)
_EXPANDED = frozenset("$`*?[{")
# Builtins that assign to the names they are given (read NAME, for NAME in, printf -v NAME).
_NAMING = frozenset(("read", "mapfile", "readarray", "vared", "getopts", "for", "select"))
_LEADING_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*", re.ASCII)
_PLAIN_NAME = re.compile(_Q_NAME + r"\Z", re.ASCII)  # a name the context grammar accepts as assigned


def _plain_name(name: str) -> bool:
    return bool(_LOCAL_NAME.fullmatch(name)) and name not in _ZSH_SPECIAL and _PLAIN_NAME.match(name) is not None


def _segments(text: str) -> list[list[tuple[str, str]]]:
    """text's simple commands, each a list of (word as written, word with quotes and backslashes removed). A
    separator (; & | ( ) { } a backtick or a newline) outside quotes ends a command; a blank outside quotes ends a
    word. Linear, and loose on purpose: it only has to find every command word, and finding more is safe."""
    segments: list[list[tuple[str, str]]] = [[]]
    raw: list[str] = []
    plain: list[str] = []
    quote = ""
    escaped = False

    def end_word() -> None:
        if raw:
            segments[-1].append(("".join(raw), "".join(plain)))
            raw.clear()
            plain.clear()

    for ch in text:
        if escaped:
            escaped = False
            raw.append(ch)
            plain.append(ch)
        elif ch == "\\" and quote != "'":
            escaped = True
            raw.append(ch)
        elif quote:
            raw.append(ch)
            if ch == quote:
                quote = ""
            else:
                plain.append(ch)
        elif ch in "'\"":
            quote = ch
            raw.append(ch)
        elif ch in " \t":
            end_word()
        elif ch in ";&|(){}`\n":
            end_word()
            if segments[-1]:
                segments.append([])
        else:
            raw.append(ch)
            plain.append(ch)
    end_word()
    return [segment for segment in segments if segment]


def changes_later_commands(text: str) -> str | None:
    """Why a record can change how later commands resolve or run, or None: alias, unalias, a function definition,
    an array assignment, hash, enable, set, setopt, shopt, trap, source or ., eval, exec, builtin, command -p,
    export, declare, typeset, local or readonly with an option, PATH, LD_ or PRELOAD anywhere, an assignment (or a
    name given to read, for, printf -v and the like) to a name plainly_literal rejects or the context grammar does
    not accept, a command word that bash expands (a''lias is alias, and $a, a glob or a brace can become one), a
    shell's startup file, and their PowerShell and zsh equivalents. Linear."""
    plain = text.replace("'", "").replace('"', "").replace("\\", "")
    found = _TAINT.search(plain)
    if found is not None:
        kind = found.lastgroup
        if kind == "word":
            return found.group("word")
        if kind == "option":
            return _TAINT_REASONS[kind].format(found.group("option"))
        return _TAINT_REASONS[kind]
    for segment in _segments(text):
        command = None
        skip = False
        named = False  # the next word is printf -v's name
        for raw, word in segment:
            if skip:
                skip = False
                continue
            assigned = _ASSIGNED.match(word)
            if assigned is not None:
                if not _plain_name(assigned.group()):
                    return "an assignment to a special, uppercase or credential name"
                continue
            if command is None:
                redirection = _REDIRECTION.match(raw)
                if redirection is not None:
                    skip = redirection.end() == len(raw)  # the target is the next word
                    continue
                if word in _BEFORE_COMMAND or (word.startswith("-") and len(word) > 1):
                    continue
                command = word
                if raw not in ("[", "[[") and any(ch in _EXPANDED for ch in raw):
                    return "a command word that the shell expands"
                continue
            if command == "printf":
                if not named and word.startswith("-v"):
                    named = word == "-v"
                    word = word[2:]
                elif named:
                    named = False
                else:
                    continue
            elif command not in _NAMING:
                continue
            name = _LEADING_NAME.match(word)
            if name is not None and not _plain_name(name.group()):
                return "a name given to " + command
    return None


# Partial matches. A rule describes the command it matched. A line that also runs a command the rule does not
# describe (a later pipeline stage that runs a shell, a command substitution, any tool the rule does not name) keeps
# the rule's gloss, marked partial, and still goes to the model. The test is default-deny: outside the part of the
# line the rule matched, only the commands below, which print, read or filter text, leave the gloss whole.
_PLAIN_COMMANDS = frozenset((
    "echo", "printf", "cat", "type", "grep", "egrep", "fgrep", "head", "tail", "sort", "uniq", "wc", "cut", "tr",
    "column", "nl", "fold", "rev", "less", "more", "jq", "xxd", "od", "hexdump", "strings", "md5sum", "sha1sum",
    "sha256sum", "sha512sum", "true", "false",
    # PowerShell's and cmd's
    "write-output", "write-host", "select-object", "select-string", "sort-object", "format-table", "format-list",
    "out-string", "out-null", "measure-object", "findstr", "get-content", "gc",
))
_INTERPRETER = re.compile(r"(?:ba|z|da|k|a|c|tc|fi)?sh|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|node|nodejs"
                          r"|lua[0-9.]*|tclsh|osascript|powershell|pwsh|cmd|iex|invoke-expression|eval|source|\."
                          r"|wscript|cscript|mshta", re.ASCII)
# Words that come before a command word and run it: they are skipped to find the command.
_RUNS_NEXT = frozenset(("sudo", "doas", "nohup", "time", "nice", "timeout", "stdbuf", "setsid", "command", "exec",
                        "builtin", "env", "busybox", "!", "{", "}", "if", "then", "do", "else", "elif", "while",
                        "until", "coproc", "noglob", "nocorrect"))
_SUDO_ARGUMENT = re.compile(r"-[A-Za-z]*[CDghprtTUu]", re.ASCII)  # a sudo or doas option that takes the next word
_SHOWN_NAME = re.compile(r"\.|[a-z0-9][a-z0-9._+-]{0,31}", re.ASCII)
_MAX_COMMANDS = 64  # a line with more commands than this is partial, unchecked
_EXPANDED_WORD = "$"  # stands for a command word the shell expands


def _command_name(words: list[str]) -> str | None:
    """The command a simple command runs, from its words with quotes removed: wrappers such as sudo, env and
    timeout, their options, assignments and redirections are skipped, any path is cut off, and the name is in lower
    case without .exe. A word the shell expands is _EXPANDED_WORD."""
    skip = False
    wrapper = ""
    for word in words:
        if skip:
            skip = False
            continue
        if not word or _ASSIGNED.match(word):
            continue
        redirection = _REDIRECTION.match(word)
        if redirection is not None:
            skip = redirection.end() == len(word)  # the target is the next word
            continue
        if wrapper and word.startswith("-") and len(word) > 1:
            skip = ((wrapper in ("sudo", "doas") and _SUDO_ARGUMENT.fullmatch(word) is not None)
                    or (wrapper, word) in (("nice", "-n"), ("env", "-u")))
            continue
        if wrapper == "timeout":
            wrapper = "timed"  # the duration
            continue
        if any(ch in _EXPANDED for ch in word):
            return _EXPANDED_WORD
        name = re.split(r"[/\\]", word)[-1].lower().removesuffix(".exe")
        if name in _RUNS_NEXT:
            wrapper = name
            continue
        return name
    return None


def _commands(text: str) -> list[tuple[int, str | None]]:
    """Each simple command in a one-line text, at any depth: pipeline stages and lists, subshells, and command and
    process substitutions in or out of double quotes. For each: where it starts, and its command (_command_name).
    Linear, and loose on purpose: finding more commands only costs model calls."""
    starts: list[int] = [0]
    words: list[list[str]] = [[]]
    current = 0
    plain: list[str] = []
    in_word = False
    quote = ""
    # For each open $( <( >( ( or backtick: its closer, whether it expands into the word around it (not a subshell's
    # parenthesis), and the quote and word state to restore.
    stack: list[tuple[str, bool, str, int, list[str], bool]] = []

    def end_word() -> None:
        nonlocal in_word
        if in_word:
            words[current].append("".join(plain))
            plain.clear()
            in_word = False

    def open_command(at: int) -> None:
        nonlocal current
        starts.append(at)
        words.append([])
        current = len(starts) - 1

    def push(closer: str, at: int, expands: bool = True) -> None:
        nonlocal quote, plain, in_word
        stack.append((closer, expands, quote, current, plain, in_word))
        quote, plain, in_word = "", [], False
        open_command(at)

    def pop() -> None:
        nonlocal quote, plain, in_word, current
        end_word()
        _, expands, quote, current, plain, in_word = stack.pop()
        if expands:
            plain.append(_EXPANDED_WORD)  # the outer word holds an expansion
            in_word = True

    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = ""
            else:
                plain.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            plain.append(text[i + 1])
            in_word = True
            i += 2
            continue
        if ch == "`":
            if stack and stack[-1][0] == "`":
                pop()
            else:
                push("`", i + 1)
            i += 1
            continue
        if text.startswith("$(", i) or (not quote and text.startswith(("<(", ">("), i)):
            push(")", i + 2)
            i += 2
            continue
        if quote == '"':
            if ch == '"':
                quote = ""
            else:
                plain.append(ch)
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            in_word = True
        elif ch == ")":
            if stack and stack[-1][0] == ")":
                pop()
        elif ch == "(":
            end_word()
            push(")", i + 1, expands=False)
        elif ch in " \t":
            end_word()
        elif ch in "|;\n" or (ch == "&" and not (i and text[i - 1] in "<>") and not text.startswith("&>", i)):
            end_word()
            while i + 1 < n and text[i + 1] in "|&;":
                i += 1
            open_command(i + 1)
        else:
            plain.append(ch)
            in_word = True
        i += 1
    end_word()
    return [(start, _command_name(said)) for start, said in zip(starts, words)]


def partial_reason(rule: Rule, text: str) -> str | None:
    """Why a rule's gloss of a one-line text is partial, or None when the rule describes all the line runs.

    The rule claims the part of the text it matches from the latest command start at which it still matches, so
    python3 gen.py | base64 -d claims only base64 -d, while curl ... | bash claims both commands. Every command that
    starts outside that part must print, read or filter text (_PLAIN_COMMANDS); anything else, a shell or interpreter
    above all, makes the gloss partial. A context rule's gloss, and a record that spans lines (only a plain heredoc
    write is claimed then), are never partial.
    """
    if rule.context or "\n" in text:
        return None
    commands = _commands(text)
    if len(commands) > _MAX_COMMANDS:
        return f"the line runs more than {_MAX_COMMANDS} commands, too many to check against the rule"
    lo, hi = 0, len(text)
    for start in sorted({start for start, _ in commands}, reverse=True):
        found = rule.regex.search(text[start:])
        if found is not None:
            lo, hi = start, start + found.end()
            break
    # A command with no command word (only assignments or redirections) runs nothing.
    outside = [name for start, name in commands
               if not lo <= start < hi and name is not None and name not in _PLAIN_COMMANDS]
    if not outside:
        return None
    name = next((name for name in outside if _INTERPRETER.fullmatch(name)), outside[0])
    if name == _EXPANDED_WORD:
        return "the line also runs a command word the shell expands, which this rule does not describe"
    shown = name if _SHOWN_NAME.fullmatch(name) else "another command"
    kind = ", a shell or interpreter," if _INTERPRETER.fullmatch(name) else ","
    return f"the line also runs {shown}{kind} which this rule does not describe"


@dataclass
class Rule:
    id: str
    regex: re.Pattern
    meaning: str
    techniques: list[str]
    artifacts: list[str]
    iocs: list[str]
    confidence: str
    context: bool
    platforms: list[str]
    examples_match: list[str]
    examples_no_match: list[str]
    file: str
    pattern: str = ""  # the regex as written, before its placeholders are expanded
    multiline: bool = False  # may claim a record that spans lines (see Library.match_record)


@dataclass
class Library:
    version: str
    rules: list[Rule]
    techniques: dict[str, Technique] = field(default_factory=dict)

    def match(self, text: str, context: bool = True, zsh: bool = False) -> Rule | None:
        """The first rule that matches text, or None to leave it to the model.

        A text that holds a blank other than space and tab, or a control character
        (normalize.has_unusual_characters), may read differently to bash than it looks, so no rule claims it. A
        context rule claims only a plainly literal text (plainly_literal; zsh for a zsh history's), and only when
        context is true: the caller passes false once its transcript unit holds a record that can change how later
        commands run (changes_later_commands) or a control character (Source.no_context)."""
        # v0.2: a per-rule literal prefilter (skip a rule whose required words are absent) would cut the
        # whole-library scan, about 100 ms per 4,200 characters in the worst case measured today, and linear: four
        # times the length takes about four times as long.
        if has_unusual_characters(text):
            return None
        literal = context and plainly_literal(text, zsh)
        for rule in self.rules:
            if (literal or not rule.context) and rule.regex.search(text):
                return rule
        return None

    def match_record(self, text: str, context: bool = True, zsh: bool = False) -> Rule | None:
        """The rule that glosses one stored record, or None to leave it to the model (see match).

        After the reader's split, a record that still spans lines is one command whose argument spans them: a
        multi-line string, an array, a substitution or a heredoc body. A rule that matches its first line describes
        that line and would hide the rest (ssh host "<commands>", sh -c '...', python -c "..."), so such a record
        may be claimed only by a rule marked multiline whose match lies wholly on the first line of a plain heredoc
        write (normalize.is_plain_heredoc_write): cat, tee or crontab copying one heredoc's body to a file, with
        nothing else that bash runs, where the body is the file's content and the write describes the whole record.
        No context rule claims it, since it is not plainly literal.
        """
        if "\n" not in text:
            return self.match(text, context, zsh)
        if has_unusual_characters(text) or not is_plain_heredoc_write(text):
            return None
        first = text.index("\n")
        for rule in self.rules:
            if rule.multiline:
                found = rule.regex.search(text)
                if found and found.end() <= first:
                    return rule
        return None


def default_dir() -> Path:
    return Path(__file__).resolve().parent / "rules"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _MatchSpec(_Strict):
    regex: str


class _ExamplesSpec(_Strict):
    match: list[str] = Field(default_factory=list)
    no_match: list[str] = Field(default_factory=list)


class _RuleSpec(_Strict):
    id: str = Field(pattern=f"^{RULE_ID}$")
    match: _MatchSpec
    meaning: str = Field(min_length=1)
    techniques: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "high"
    context: bool = False
    multiline: bool = False
    platforms: list[str] = Field(default_factory=list)
    examples: _ExamplesSpec = Field(default_factory=_ExamplesSpec)


_LISTS = ("techniques", "artifacts", "iocs", "platforms")


def _no_unknown_keys(mapping: dict, known, where: str, prefix: str = "") -> None:
    unknown = sorted(prefix + str(key)[:40] for key in mapping if key not in known)
    if unknown:
        raise LibraryError(f"{where}: unknown key(s) {', '.join(unknown[:10])}")


def _string_list(value: object, where: str, name: str) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise LibraryError(f"{where}: {name} must be a list of strings")
    if len(value) > MAX_ITEMS:
        raise LibraryError(f"{where}: {name} has {len(value)} items; at most {MAX_ITEMS} are allowed")
    if not all(isinstance(item, str) for item in value):
        raise LibraryError(f"{where}: {name} must be a list of strings")


def _screen(raw: dict, where: str) -> None:
    """Reject unknown keys and malformed lists before pydantic sees the rule.

    YAML aliases let a small file expand into a huge nested structure. These checks look only at the keys and at
    the top level of each list, so they never walk into one, and pydantic only ever sees lists of strings.
    """
    _no_unknown_keys(raw, _RuleSpec.model_fields, where)
    for name in _LISTS:
        _string_list(raw.get(name), where, name)
    match, examples = raw.get("match"), raw.get("examples")
    if isinstance(match, dict):
        _no_unknown_keys(match, _MatchSpec.model_fields, where, "match.")
    if isinstance(examples, dict):
        _no_unknown_keys(examples, _ExamplesSpec.model_fields, where, "examples.")
        for name in _ExamplesSpec.model_fields:
            _string_list(examples.get(name), where, f"examples.{name}")


@functools.lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    """Compile a rule regex with the parser's warnings as errors. Python 3.10 only warns about a global flag that is
    not at the start (a(?i)b), where 3.11 and later raise, and every version only warns about a possible nested set
    or set operation ([[a], [a&&b]); as errors, every Python version rejects the same rules.

    A pattern compiled here is kept (a rejected one is not), so a library loaded again compiles nothing. On a miss,
    re's own cache is purged first: it would return a pattern compiled elsewhere without parsing it again, and so
    without the warning. Purging once per load would not help, since it also drops the rules compiled by the last
    load."""
    re.purge()
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        warnings.simplefilter("error", FutureWarning)
        return re.compile(pattern, re.ASCII)


def _rule(raw: object, file: str, seen: set[str], index: int) -> Rule:
    if not isinstance(raw, dict):
        raise LibraryError(f"{file}: each rule must be a mapping")
    rid = raw.get("id")
    where = f"{file}: rule {rid!r}" if isinstance(rid, str) and len(rid) <= 64 else f"{file}: rule #{index}"
    _screen(raw, where)
    try:
        spec = _RuleSpec.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors(include_url=False, include_input=False, include_context=False)[0]
        loc = ".".join(str(part) for part in first["loc"])
        raise LibraryError(f"{where}: invalid {loc} ({first['msg']})") from None
    rid = spec.id
    if rid in seen:
        raise LibraryError(f"{file}: missing or duplicate rule id {rid!r}")
    seen.add(rid)
    try:
        regex = _compile(expand(spec.match.regex))
    except (re.error, DeprecationWarning, FutureWarning, RecursionError, OverflowError, LibraryError) as exc:
        raise LibraryError(f"rule {rid}: bad match.regex ({exc})") from None
    if regex.search("") is not None:
        raise LibraryError(f"rule {rid}: match.regex matches the empty string, so it would match every line")
    if spec.context and spec.techniques:
        raise LibraryError(f"rule {rid}: context rules carry no techniques")
    if spec.context and spec.multiline:
        raise LibraryError(f"rule {rid}: context rules read every line already, so multiline is for the others")
    if not spec.context and not spec.techniques:
        raise LibraryError(f"rule {rid}: needs at least one technique, or context: true")
    bad = sorted(set(spec.iocs) - set(IOC_TYPES))
    if bad:
        raise LibraryError(f"rule {rid}: unknown IOC type(s) {', '.join(bad)}")
    return Rule(id=rid, regex=regex, meaning=spec.meaning, techniques=list(spec.techniques),
                artifacts=list(spec.artifacts), iocs=list(spec.iocs), confidence=spec.confidence,
                context=spec.context, platforms=list(spec.platforms), examples_match=list(spec.examples.match),
                examples_no_match=list(spec.examples.no_match), file=file, pattern=spec.match.regex,
                multiline=spec.multiline)


_YAML_OPENERS = (yaml.FlowSequenceStartToken, yaml.FlowMappingStartToken, yaml.BlockSequenceStartToken,
            yaml.BlockMappingStartToken)
_CLOSERS = (yaml.FlowSequenceEndToken, yaml.FlowMappingEndToken, yaml.BlockEndToken)


def _check_depth(text: str, name: str) -> None:
    """Refuse YAML nested deeper than MAX_DEPTH, reading tokens only.

    PyYAML's scanner does work in proportion to the current depth for every token, so deep nesting costs time in
    the square of its depth (5,000 levels take seconds) before the parser's recursion fails. Stopping at
    MAX_DEPTH keeps that cost linear.
    """
    depth = 0
    for token in yaml.scan(text, Loader=yaml.SafeLoader):
        if isinstance(token, _YAML_OPENERS):
            depth += 1
            if depth > MAX_DEPTH:
                raise LibraryError(f"{name}: cannot read the YAML (nested deeper than {MAX_DEPTH} levels)")
        elif isinstance(token, _CLOSERS):
            depth -= 1


def _load_file(path: Path, seen: set[str]) -> list[Rule]:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise LibraryError(f"{path.name}: larger than 1 MiB")
    try:
        text = path.read_text(encoding="utf-8")
        _check_depth(text, path.name)
        docs = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, UnicodeDecodeError) as exc:
        detail = str(exc).splitlines()[0][:200] if str(exc) else ""
        raise LibraryError(f"{path.name}: cannot read the YAML ({type(exc).__name__}: {detail})") from None
    if docs is None:
        return []
    if not isinstance(docs, list):
        raise LibraryError(f"{path.name}: expected a list of rules")
    try:
        return [_rule(raw, path.name, seen, index) for index, raw in enumerate(docs, 1)]
    except (RecursionError, TypeError, AttributeError) as exc:
        raise LibraryError(f"{path.name}: malformed rule ({type(exc).__name__})") from None


def load_library(directory: str | Path | None = None, resolver=None) -> Library:
    folder = Path(directory) if directory else default_dir()
    version = (folder / "VERSION").read_text(encoding="utf-8").strip()
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted(folder.glob("*.yaml")):
        rules.extend(_load_file(path, seen))
    library = Library(version=version, rules=rules)
    if resolver is not None:
        for rule in rules:
            for tid in rule.techniques:
                key = tid.upper()
                if key in library.techniques:
                    continue
                technique = resolver.check(tid)
                if technique.status in ("revoked", "unknown"):
                    detail = f" (replaced by {', '.join(technique.replaced_by)})" if technique.replaced_by else ""
                    raise LibraryError(f"rule {rule.id} in {rule.file}: technique {tid} is {technique.status}{detail}")
                library.techniques[key] = technique
    return library


def gloss_for(library: Library, rule: Rule, text: str, at: str) -> Gloss:
    techniques = [library.techniques.get(t.upper(), Technique(id=t.upper())).model_copy(deep=True)
                  for t in rule.techniques]
    return Gloss(source="none" if rule.context else "rule", rule_id=rule.id, meaning=rule.meaning,
                 techniques=techniques, artifacts=list(rule.artifacts), iocs=indicators(text, rule.iocs),
                 confidence=rule.confidence, by=f"rules {library.version}", at=at)


# The timing guard. Stored lines are at most about 4,200 characters, so every rule is timed on lines that long,
# built from its own literal words, its examples and the shapes below. The primary test is growth: a rule fails when
# four times the length takes more than SCALE_LIMIT times as long, which holds on a fast machine and a slow runner
# alike. TIME_LIMIT is only a ceiling for one line, set well above what any linear rule takes even on a slow runner,
# and confirmed with the best of three runs. The line grows in small steps first, so an exponential regex is caught
# by the ceiling while it is still cheap to run, before its growth could be measured at full length.
TIME_LIMIT = 0.025
SCALE_LIMIT = 8.0
GUARD_LENGTH = 4200
_SCALE_FLOOR = 0.0005  # below this, a ratio is mostly timer noise
_LADDER = (8, 12, 16, 20, 24, 28, 32, 40, 48, 64, 256, GUARD_LENGTH // 4, GUARD_LENGTH)
SHAPES = (
    # Shapes that made earlier forms of the rules quadratic: repeated redirections, iex after a number, alternating
    # command words, ssh before a tab, and repeated downloader words.
    ">", "1 " + "ie" + "x ", "cat cp ", "ssh\t", "wg" + "et wg" + "et ",
    # Separators, quotes and blanks, and an unclosed ${, which once made the context grammar quadratic.
    ">>", "> ", "|", "| ", ";", "&", "&&", "(", "{", "`", "$(", "<(", "'", '"', " ", "\t", "\\", "${",
    # Option words, assignments, paths and redirections.
    "-", "- ", "-a ", "--", "a", "a ", "a=b ", "/", "a/", "./", "x", "1", "1 ", "0>&1 ", "2>&1 ",
    # The command position: sudo, its options and the wrappers.
    "sudo ", "sudo -u a ", "sudo -a ", "nohup ", "env a=b ", "timeout -k 1 1 ", "nice -n 1 ", "do ", "! ",
    "cmd /c ", "powershell -a b ",
    # Commented lines, which once had two readings each in the context grammar.
    "# \n", "#;;\n", "x=1 # c \n",
    # The words of a test, which an operator may read with the double-quoted expansion next to it.
    '"$a" ', '-n "$a" ', '= "$a" ', '[ "$a" ', '"$a" = ',
    # A command after ), which the context grammar reads as a separator: a lookahead that read on from every read to
    # the end of the line was quadratic there.
    ")read ", "read )",
    # Texts of many lines, which the unanchored rules scan whole.
    "\n", "a\n", "sudo \n", "| \n",
    # Whitespace that bash reads as part of a word but Python's \s reads as a blank (a no-break space, an ideographic
    # space, a vertical tab): a scan that reads it both ways is quadratic.
    chr(0xA0), chr(0xA0) + "a", chr(0x3000), chr(0x0B), "a" + chr(0xA0) + ") ",
)
_CLASS = re.compile(r"\[\^?\]?(?:\\.|[^\]\\])*\]")
_HEX_ESCAPE = re.compile(r"\\x([0-9A-Fa-f]{2})")
_LETTER_ESCAPE = re.compile(r"\\[A-Za-z0-9]")
_BRACES = re.compile(r"\{[0-9,]*\}|\{[a-z]+\}")
_GROUP = re.compile(r"\(\?(?:[:=!]|<[=!]|P<\w+>|[aiLmsux-]+[:)])")
_LITERAL_RUN = re.compile(r"(?:\\[^A-Za-z0-9]|[^\\()\[\]{}|?*+^$.])+")
_UNESCAPE = re.compile(r"\\(.)")


def _literals(pattern: str) -> list[str]:
    """The literal words of a regex as written, such as wget or /dev/tcp/, for the timing guard."""
    text = _CLASS.sub("|", pattern)
    text = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    text = _LETTER_ESCAPE.sub("|", text)
    text = _BRACES.sub("|", text)
    text = _GROUP.sub("|", text)
    words = {_UNESCAPE.sub(r"\1", run).strip() for run in _LITERAL_RUN.findall(text)}
    return sorted(word for word in words if len(word) >= 2)


def example_words(library: Library) -> list[str]:
    """Every whitespace-separated word, of two characters or more, of every example in the library."""
    return sorted({word for rule in library.rules for example in rule.examples_match + rule.examples_no_match
                   for word in example.split() if len(word) >= 2})


def timing_units(rule: Rule, words: Iterable[str] = ()) -> list[str]:
    """The units the timing guard repeats into long lines: SHAPES, the rule's literal words, its examples, and
    example words repeated with no blanks between them.

    The example words are this rule's own, and those of words (the whole library's, from run_examples) that contain
    one of the rule's literal words of four characters or more, such as /usr/bin/find for a rule that names find.
    Each is used alone, followed by "." and followed by ",": an unbroken run of one word is the shape that makes a
    scan from every occurrence of a literal quadratic.
    """
    literals = _literals(rule.pattern or rule.regex.pattern)
    units = list(SHAPES)
    for word in literals:
        units += [word, word + " "]
    own = rule.examples_match + rule.examples_no_match
    units += own
    keys = [literal for literal in literals if len(literal) >= 4]
    chosen = {word for example in own for word in example.split() if len(word) >= 2}
    chosen |= {word for word in words if any(key in word for key in keys)}
    for word in sorted(chosen):
        units += [word, word + ".", word + ","]
    return list(dict.fromkeys(unit for unit in units if unit))


def adversarial_line(unit: str, length: int) -> str:
    """unit repeated to length characters, the last one a NUL that no rule expects, so no match ends early."""
    return (unit * (length // len(unit) + 1))[: length - 1] + "\x00"


def _best(search, text: str, reps: int) -> float:
    out = math.inf
    for _ in range(reps):
        start = time.perf_counter()
        search(text)
        out = min(out, time.perf_counter() - start)
    return out


def _scale_lengths(unit: str) -> tuple[int, int]:
    """About GUARD_LENGTH / 4 and four times that, both ending at the same point of the unit, so the two lines differ
    only in how many units they hold, not in how the last one is cut."""
    small = max(GUARD_LENGTH // 4 // len(unit), 1) * len(unit) + 1
    return small, 4 * (small - 1) + 1


def _scale_failure(rule: Rule, unit: str) -> str | None:
    small_line, large_line = (adversarial_line(unit, n) for n in _scale_lengths(unit))
    search = rule.regex.search
    if (search(small_line) is None) != (search(large_line) is None):
        return None  # one line matches early and the other does not: the times do not compare
    for reps in (3, 7):  # timer noise rarely survives a second, longer look
        small, large = _best(search, small_line, reps), _best(search, large_line, reps)
        if large <= _SCALE_FLOOR or large <= SCALE_LIMIT * small:
            return None
    return f"{rule.id}: superlinear on lines of {unit!r}: {large / small:.1f} times slower for 4 times the length"


def _time_rule(rule: Rule, units: tuple[str, ...]) -> str | None:
    search = rule.regex.search
    slowest: list[tuple[float, str]] = []
    for unit in units:
        elapsed = 0.0
        for length in _LADDER:
            line = adversarial_line(unit, length)
            elapsed = _best(search, line, 1)
            if elapsed > TIME_LIMIT:
                elapsed = _best(search, line, 3)  # one slow run can be noise; three cannot
                if elapsed > TIME_LIMIT:
                    # At full length the shorter rungs passed, so growth can be measured safely, and growth is
                    # the primary finding when it is the cause.
                    failure = _scale_failure(rule, unit) if length == GUARD_LENGTH else None
                    return failure or (f"{rule.id}: {elapsed * 1000:.1f} ms on a {length}-character line of "
                                       f"{unit!r} (limit {TIME_LIMIT * 1000:.0f} ms)")
        slowest.append((elapsed, unit))
    for elapsed, unit in sorted(slowest, reverse=True)[:3]:  # growth shows first where the time is largest
        if elapsed <= _SCALE_FLOOR:
            break
        failure = _scale_failure(rule, unit)
        if failure:
            return failure
    return None


_TIMED: dict[tuple[str, str, tuple[str, ...]], str | None] = {}  # one timing per rule and process


def _timing_failure(rule: Rule, words: Iterable[str] = ()) -> str | None:
    units = tuple(timing_units(rule, words))
    key = (rule.id, rule.regex.pattern, units)
    if key not in _TIMED:
        _TIMED[key] = _time_rule(rule, units)
    return _TIMED[key]


def run_examples(library: Library) -> list[str]:
    """Time every rule, then check every example. A rule that fails the timing guard is left out of the example
    checks, since running it could take far too long."""
    failures: list[str] = []
    usable: list[Rule] = []
    words = example_words(library)
    for rule in library.rules:
        failure = _timing_failure(rule, words)
        if failure:
            failures.append(failure)
        else:
            usable.append(rule)

    def first_match(text: str) -> Rule | None:
        return next((rule for rule in usable if rule.regex.search(text)), None)

    for rule in usable:
        for example in rule.examples_match:
            got = first_match(example)
            if got is None or got.id != rule.id:
                failures.append(f"{rule.id}: expected to match {example!r}, but {got.id if got else 'no rule'} matched")
        for example in rule.examples_no_match:
            if rule.regex.search(example):
                failures.append(f"{rule.id}: should not match {example!r}")
    return failures
