"""Shell and PowerShell script reader."""

from __future__ import annotations

import bisect
import re

from ..normalize import MAX_LINE, join_logical_records, normalize_text
from ..textshow import show_controls
from . import RawCommand, split_lines, unjoined_warnings


def read_script(text: str, powershell: bool = False, warnings: list[str] | None = None) -> list[RawCommand]:
    """Read a shell or PowerShell script. Given a warnings list, a bash script adds the lines left unjoined to it."""
    lines = split_lines(text)
    if powershell:
        return [RawCommand(line=k, text=t) for k, t in join_powershell_lines(lines)]
    unjoined: list[tuple[int, int, str]] = []
    joined = join_logical_records(lines, unjoined=unjoined)
    if warnings is not None:
        warnings.extend(unjoined_warnings(unjoined))
    return [RawCommand(line=k, text=t, line_starts=starts) for k, t, starts in joined]


# A .ps1 script follows PowerShell's rules (about_Quoting_Rules, about_Comments, about_Special_Characters, checked
# against PowerShell 5.1's parser) and none of bash's: no heredocs, no backslash escapes, no bash comment rule.
# - Quotes come in two families: ' and U+2018 to U+201B are single quotes; " and U+201C to U+201E are double quotes.
#   Any member opens or closes a string of its family. Two members in a row are an escaped quote, which scans the
#   same as a string that closes and reopens.
# - '...' is literal. In "...", and outside strings, a backtick escapes the next character. A final backtick
#   continues the line, so a line continues when it ends in an odd run of backticks outside strings and comments.
# - In "...", an unescaped $( opens a subexpression: code, in which quotes open nested strings, parentheses are
#   counted, and the matching ) returns to the string. $$ is a variable, so $$( opens nothing. Inside the code,
#   # and <# start comments and a line ending in @ and a quote starts a here-string, as in PowerShell.
# - Strings, subexpressions, block comments and here-strings inside subexpressions may span lines. The scan keeps a
#   stack of them across lines but never groups their lines: each stays its own logical line, and a line inside
#   one cannot continue or open a here-string.
# - # starts a comment to the end of the line, even inside a word. PowerShell keeps a#b as one word, so this may
#   split a command PowerShell would join, and it would miss a <# that PowerShell reads after a#b. So when a
#   top-level # touches the character before it, a <# later on its line that no #> follows is taken as an open
#   block comment (see _after_line_comment). Inside a subexpression, the same # rule applies, without that guess.
# - <# ... #> is a block comment.
# - At the top level, a line ending in @ and a quote (then only blanks) opens a here-string. The first later line
#   that starts with a quote of the same family and @ closes it, and the lines between are grouped. Code may follow
#   the closer. A here-string that never closes consumes nothing.
# When a construct that an earlier line opened closes, the scan goes on after it, except that this logical line
# never opens a here-string: the block comment may have been a guess, and its #> may sit somewhere PowerShell reads
# differently.
# A joined record is only kept whole while it fits in MAX_LINE as it will be stored: invisible characters shown by
# code point (show_controls), then normalized. A longer one would be truncated, so each of its physical lines becomes
# a record of its own instead (see _split_if_too_long).
# Known limitations:
# - the scan can still fall out of step with PowerShell on crafted input: for example a # inside a word (a#b, at the
#   top level or within a subexpression) hides a quote after it, and a braced variable name such as ${a"b} holds a
#   quote. The scan may then join the wrong lines into a record, but the cap keeps every such record short and
#   visible, so this can misattribute a few lines but cannot hide a command through truncation;
# - nesting deeper than _MAX_DEPTH (only crafted input goes there) ends the scan. From that line on, every physical
#   line is its own logical line, with no continuation joining and no here-string grouping.

# Built with chr() so this file stays ASCII.
_SINGLE_QUOTES = "'" + "".join(chr(c) for c in range(0x2018, 0x201C))
_DOUBLE_QUOTES = '"' + "".join(chr(c) for c in range(0x201C, 0x201F))
_FAMILY = {**dict.fromkeys(_SINGLE_QUOTES, _SINGLE_QUOTES), **dict.fromkeys(_DOUBLE_QUOTES, _DOUBLE_QUOTES)}
_ANY_SINGLE = f"[{_SINGLE_QUOTES}]"
_ANY_DOUBLE = f"[{_DOUBLE_QUOTES}]"

# The tokens that matter in code. A complete string with no backtick or $ in it is skipped whole, which saves a step
# per string; any other string starts at a lone quote. Then a run of backticks, # or <#, and a here-string header
# (@ and a quote, then only blanks to the end of the line). Inside a subexpression, also runs of parentheses.
_CODE_TOKENS = (
    rf"(?P<string>{_ANY_SINGLE}[^{_SINGLE_QUOTES}]*{_ANY_SINGLE}|{_ANY_DOUBLE}[^`${_DOUBLE_QUOTES}]*{_ANY_DOUBLE})"
    rf"|`+|{_ANY_SINGLE}|{_ANY_DOUBLE}|#|<#|@(?:{_ANY_SINGLE}|{_ANY_DOUBLE})[ \t]*\Z"
)
_CODE = re.compile(_CODE_TOKENS)
_SUBEXPRESSION_CODE = re.compile(_CODE_TOKENS + r"|[()]+")
# Top-level code as split_powershell_statements scans it: also a statement separator (;, or the && and || of
# PowerShell 7's pipeline chains) or a bracket, which it counts so a ; inside ( ), $( ), @( ), { } or @{ } stays put.
_STATEMENT_CODE = re.compile(_CODE_TOKENS + r"|(?P<statement>[;(){}]|&&|\|\|)")
_SINGLE_QUOTE = re.compile(_ANY_SINGLE)
# Inside "...": a run of backticks, a run of $, and the closing quote. Each $$ in a run is a variable, so only the
# last $ of an odd run can open a subexpression, with the ( right after it. The run is matched in one step and its
# length checked in Python: Python 3.10's re handles a repeated group such as (?:\$\$)+ slowly on long runs.
_IN_DOUBLE_QUOTES = re.compile(rf"`+|\$+|{_ANY_DOUBLE}")
# A subexpression with nothing in it that changes the scan (no quote, parenthesis, backtick or #), skipped whole.
_PLAIN_SUBEXPRESSION = re.compile(rf"\([^()`#{_SINGLE_QUOTES}{_DOUBLE_QUOTES}]*\)")

# What the scan stack holds, innermost last. Each entry is [kind, value]: value is the parenthesis depth of a
# subexpression, or the quote family that closes a here-string.
_SINGLE, _DOUBLE, _SUBEXPRESSION, _BLOCK_COMMENT, _NESTED_HERE_STRING = range(5)
_MAX_DEPTH = 64

# How a line ends.
_ENDS, _CONTINUES, _OPEN, _HERE_STRING, _TOO_DEEP = range(5)


def _paren_run(run: str, depth: int) -> tuple[int, int]:
    """Apply a run of ( and ) to a subexpression's depth.

    Returns (new depth, characters used). The run is used up to the ) that brings the depth to 0, or whole.
    """
    closing = run.count(")")
    if closing < depth:  # it cannot reach 0, so only the totals matter
        return depth + len(run) - 2 * closing, len(run)
    for used, ch in enumerate(run, start=1):
        depth += 1 if ch == "(" else -1
        if depth == 0:
            return 0, used
    return depth, len(run)


def _after_line_comment(line: str, start: int, stack: list[list]) -> tuple[int, str]:
    """How a line ends when its scan reaches a top-level # at line[start] and takes the rest as a comment.

    When the # touches the character before it, PowerShell may read code there instead (a#b is one word to it), so
    a <# later on the line that no #> follows is taken as an open block comment. That can only over-report: the
    lines after it are not joined to anything. A # at the start of the line or after whitespace is a real comment.
    """
    if start == 0 or line[start - 1].isspace():
        return _ENDS, ""
    opener = line.rfind("<#", start)
    if opener >= 0 and line.find("#>", opener + 2) < 0:
        stack.append([_BLOCK_COMMENT, 0])
        return _OPEN, ""
    return _ENDS, ""


def _scan_line(line: str, stack: list[list], pos: int = 0, statements: list | None = None) -> tuple[int, str]:
    """Scan a line from pos, starting in the contexts an earlier line left open on the stack, which it updates.

    Returns (_CONTINUES, ""), (_ENDS, ""), (_OPEN, "") when a context is still open at the end of the line,
    (_HERE_STRING, family) for a top-level here-string header, or (_TOO_DEEP, "") past _MAX_DEPTH.

    Given a statements list (only split_powershell_statements passes one), the scan also appends each statement
    separator or bracket it meets in top-level code, as (index, token). Without it, the scan is the joiner's.
    """
    top_level_code = _CODE if statements is None else _STATEMENT_CODE
    while True:
        kind = stack[-1][0] if stack else None
        if kind is None or kind == _SUBEXPRESSION:  # code
            found = (top_level_code if kind is None else _SUBEXPRESSION_CODE).search(line, pos)
            if found is None:
                return (_ENDS if kind is None else _OPEN), ""
            if found.lastgroup == "string":
                pos = found.end()
                continue
            if found.lastgroup == "statement":
                statements.append((found.start(), found.group()))
                pos = found.end()
                continue
            token, start, pos = found.group(), found.start(), found.end()
            first = token[0]
            if first == "`":
                if pos == len(line):
                    if kind is not None:
                        return _OPEN, ""
                    return (_CONTINUES if len(token) % 2 else _ENDS), ""
                pos += len(token) % 2  # an odd run of backticks escapes the next character
            elif first == "#":
                if kind is None:
                    return _after_line_comment(line, start, stack)
                return _OPEN, ""  # the comment runs to the end of the line; the subexpression stays open
            elif first == "<":  # <#
                close = line.find("#>", pos)
                if close >= 0:
                    pos = close + 2
                elif len(stack) >= _MAX_DEPTH:
                    return _TOO_DEEP, ""
                else:
                    stack.append([_BLOCK_COMMENT, 0])
                    return _OPEN, ""
            elif first == "@":  # a here-string header
                if kind is None:
                    return _HERE_STRING, _FAMILY[token[1]]
                if len(stack) >= _MAX_DEPTH:
                    return _TOO_DEEP, ""
                stack.append([_NESTED_HERE_STRING, _FAMILY[token[1]]])
                return _OPEN, ""
            elif first in "()":  # a run of parentheses inside a subexpression
                depth, used = _paren_run(token, stack[-1][1])
                if depth == 0:
                    stack.pop()
                    pos = start + used
                else:
                    stack[-1][1] = depth
            elif len(stack) >= _MAX_DEPTH:
                return _TOO_DEEP, ""
            else:  # a quote opens a string
                stack.append([_DOUBLE if first in _DOUBLE_QUOTES else _SINGLE, 0])
        elif kind == _DOUBLE:
            found = _IN_DOUBLE_QUOTES.search(line, pos)
            if found is None:
                return _OPEN, ""
            token, pos = found.group(), found.end()
            if token[0] == "`":
                pos += len(token) % 2
            elif token[0] == "$":
                if len(token) % 2 and line.startswith("(", pos):  # the run's last $ opens a subexpression
                    plain = _PLAIN_SUBEXPRESSION.match(line, pos)
                    if plain is not None:
                        pos = plain.end()
                    elif len(stack) >= _MAX_DEPTH:
                        return _TOO_DEEP, ""
                    else:
                        stack.append([_SUBEXPRESSION, 1])
                        pos += 1
            else:  # the closing quote
                stack.pop()
        elif kind == _SINGLE:
            close = _SINGLE_QUOTE.search(line, pos)
            if close is None:
                return _OPEN, ""
            stack.pop()
            pos = close.end()
        elif kind == _BLOCK_COMMENT:
            close = line.find("#>", pos)
            if close < 0:
                return _OPEN, ""
            stack.pop()
            pos = close + 2
        else:  # a here-string inside a subexpression, closed only by a line that starts with its quote and @
            if pos == 0 and line[1:2] == "@" and line[0] in stack[-1][1]:
                stack.pop()
                pos = 2
            else:
                return _OPEN, ""


class _HereStringClosers:
    """Finds the line that closes a here-string: the first one that starts with a quote of its family and @.

    The lines are indexed once per family, on first use, so many unclosed headers never rescan the input.
    """

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self._index: dict[str, list[int]] = {}

    def find(self, family: str, start: int) -> int | None:
        """Index of the first closing line at or after start, or None if no line closes."""
        if family not in self._index:
            self._index[family] = [k for k, line in enumerate(self._lines) if line[1:2] == "@" and line[0] in family]
        found = self._index[family]
        k = bisect.bisect_left(found, start)
        return found[k] if k < len(found) else None


def _stored_length(text: str) -> int:
    """The length text is stored at: each invisible character shown by its code point (up to 10 characters for one),
    then normalized, as the parse stage stores a line."""
    return len(normalize_text(show_controls(text)))


def _split_if_too_long(lines: list[str], first: int, last: int, text: str) -> list[tuple[int, str]]:
    """The records for text, the logical line that lines[first] to lines[last] were joined into.

    One record, unless its stored text would pass MAX_LINE: then normalization would truncate it, and a scan mismatch
    could hide a command in the part cut off. Each physical line then becomes its own record, which can only
    over-report. The text is measured once per joined record, so this stays linear.
    """
    if _stored_length(text) > MAX_LINE:
        return [(k + 1, lines[k].strip()) for k in range(first, last + 1) if lines[k].strip()]
    return [(first + 1, text)] if text else []


def join_powershell_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Join PowerShell script lines into logical commands.

    A continued line drops its backtick and joins the next line with a space. A top-level here-string spanning lines
    joins them with newlines, through its closing line. Nothing else that spans lines is joined. Returns (1-based
    number of the first physical line, text) pairs and drops blank lines.
    """
    out: list[tuple[int, str]] = []
    closers = _HereStringClosers(lines)
    stack: list[list] = []  # the contexts left open at the end of the last line, innermost last
    i = 0
    while i < len(lines):
        start = i
        pieces = [lines[i]]
        pos = 0
        started_open = bool(stack)  # then this logical line never opens a here-string (see the top of this module)
        while True:
            how, family = _scan_line(lines[i], stack, pos)
            if how == _CONTINUES and i + 1 < len(lines):
                pieces[-1] = pieces[-1][:-1].rstrip()
                i += 1
                pieces.append(" " + lines[i].lstrip())
                pos = 0
                continue
            if how == _HERE_STRING and not started_open:
                end = closers.find(family, i + 1)
                if end is not None:
                    pieces.extend("\n" + line for line in lines[i + 1 : end + 1])
                    pos = 2
                    i = end
                    continue
            break
        text = "".join(pieces).strip()
        if i > start:  # a joined record
            out.extend(_split_if_too_long(lines, start, i, text))
        elif text:
            out.append((start + 1, text))
        i += 1
        if how == _TOO_DEEP:  # from here on, every physical line is its own logical line
            out.extend((k, line.strip()) for k, line in enumerate(lines[i:], start=i + 1) if line.strip())
            break
    return out


def split_powershell_statements(text: str) -> list[str]:
    """Split one PowerShell record on ;, && and || in top-level code, as split_commands does for bash.

    The scan is the joiner's (_scan_line), so quotes, backtick escapes, $( ) inside strings, comments and
    here-strings are honored the same way: a ; inside any of them does not split. Neither does a ; inside ( ),
    $( ), @( ), { } or @{ }, which are counted. && and || are PowerShell 7's pipeline chain operators. Text that
    spans lines, such as a here-string, is returned whole, as split_commands does.

    The scan's known limitations (see the top of this module) apply, and crafted text can also leave a quote or a
    bracket open, so a misread can leave statements together. A part that normalization would then truncate could
    hide a statement in the text it cuts off, so such a part is split at every separator instead (_split_if_truncated).
    """
    if "\n" in text:
        return [text]
    found: list[tuple[int, str]] = []
    _scan_line(text, [], 0, found)
    parts: list[str] = []
    start = depth = 0
    for index, token in found:
        if token in ("(", "{"):
            depth += 1
        elif token in (")", "}"):
            depth = max(depth - 1, 0)
        elif depth == 0:
            parts.append(text[start:index])
            start = index + len(token)
    parts.append(text[start:])
    return [piece for part in parts for piece in _split_if_truncated(part.strip()) if piece]


_ANY_SEPARATOR = re.compile(r";|&&|\|\|")


def _split_if_truncated(part: str) -> list[str]:
    """[part], unless its stored text would pass MAX_LINE: then its pieces between every ;, && and ||, in quotes or not.

    Like _split_if_too_long, this can only over-report. The part is measured as it will be stored, its invisible
    characters shown first (show_controls). Normalizing at most triples a text's length (a "." becomes "[.]"), so a
    shown part of up to a third of MAX_LINE is never normalized here.
    """
    shown = show_controls(part)
    if len(shown) * 3 <= MAX_LINE or len(normalize_text(shown)) <= MAX_LINE:
        return [part]
    return [piece.strip() for piece in _ANY_SEPARATOR.split(part) if piece.strip()]
