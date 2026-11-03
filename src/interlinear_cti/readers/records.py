"""Helpers the agent and C2 log readers share. Standard library only (runs in the sandbox)."""

from __future__ import annotations

import json
import os
import re
import shlex

from . import RawCommand, epoch_to_iso, iso_to_utc, split_lines

_MAX_SHOWN = 40  # characters of a record's type or role that a warning may quote
# A Sliver operator config holds an operator's credentials (token, private key), not a log: whichever reader meets one,
# it gives no line, only a warning, so the credentials never reach the transcript or the model.
CONFIG_KEYS = frozenset(("operator", "token", "lhost", "lport", "private_key"))
CONFIG_NOTE = "a Sliver operator config, which holds credentials, not a log; not read"
_SHELLS = frozenset(("bash", "sh", "zsh", "dash", "ash", "ksh"))
_SHELL_FLAGS = frozenset(("-c", "-lc", "-cl", "-ic", "-ci", "-lic", "-ilc"))
_DIGITS = re.compile(r"[0-9]{1,20}")


def is_operator_config(record: object) -> bool:
    return isinstance(record, dict) and CONFIG_KEYS <= record.keys()


def as_text(value: object) -> str:
    """A string as it is; anything else as JSON with sorted keys, as the generic agent log reader writes it."""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def record_text(value: object) -> str:
    """A record written back as JSON for a line kept whole, or a description when it cannot be: on Python 3.14,
    json.dumps, repr and str can overflow the stack at depths json.loads still accepts."""
    try:
        return as_text(value)
    except (RecursionError, ValueError):
        return f"[a {type(value).__name__} that cannot be written back as JSON]"


def shown(value: object) -> str:
    """A record's type or role for a warning: a short string quoted, else only its kind, so a warning never carries a
    long attacker-chosen value. Parse defangs and escapes every warning after this."""
    if isinstance(value, str):
        return repr(value) if len(value) <= _MAX_SHOWN else "a long string"
    return "none" if value is None else f"a {type(value).__name__}"


def json_records(text: str):
    """Yield (line number, line, record) for each non-blank line, where record is the parsed JSON value, or None when
    the line is not JSON. split_lines, not splitlines: JSON strings may hold a raw U+2028, U+2029 or \\x85."""
    for number, line in enumerate(split_lines(text), start=1):
        if not line.strip():
            continue
        try:
            yield number, line, json.loads(line)
        except (ValueError, RecursionError):
            yield number, line, None


def kept_whole(number: int, line: str, warnings: list[str], why: str, actor: str = "unknown") -> RawCommand:
    """A line no reader rule covers, kept whole with a warning, so nothing in the file drops out silently."""
    warnings.append(f"line {number}: {why}; kept as an unknown line" if actor == "unknown"
                    else f"line {number}: {why}; kept the raw line")
    return RawCommand(line=number, text=line, actor=actor)


def read_safely(read, record: object, number: int, line: str, out: list[RawCommand], warnings: list[str]) -> None:
    """Run read(record, number, line, out, warnings) for one record. A record of a shape it does not expect, which
    raises, is kept whole with a warning that names only the error's type, so one crafted record never makes parse
    skip the whole file. Whatever the record gave before the error is dropped: a record is read whole or kept whole."""
    lines, notes = len(out), len(warnings)
    try:
        read(record, number, line, out, warnings)
    except Exception as exc:  # noqa: BLE001 - the message can carry attacker text, so only the type is kept
        del out[lines:]
        del warnings[notes:]
        out.append(kept_whole(number, line, warnings, f"record not read ({type(exc).__name__})"))


def iso_ts(value: object, number: int, warnings: list[str]) -> str | None:
    """An ISO-8601 timestamp in UTC, or None, with a warning when a value is there but cannot be read."""
    ts = iso_to_utc(value)
    if value is not None and ts is None:
        warnings.append(f"line {number}: unparseable timestamp {shown(value)}")
    return ts


def epoch_ts(value: object, number: int, warnings: list[str], per_second: int = 1) -> str | None:
    """Epoch time (seconds, or milliseconds with per_second=1000) in UTC, or None. A bool is not a number here, and
    a string must be plain digits."""
    seconds = None
    if isinstance(value, bool):
        seconds = None
    elif isinstance(value, int):
        seconds = value // per_second
    elif isinstance(value, float) and value == value and abs(value) < 1e15 * per_second:
        seconds = int(value // per_second)
    elif isinstance(value, str) and _DIGITS.fullmatch(value):
        seconds = int(value) // per_second
    ts = epoch_to_iso(seconds) if seconds is not None else None
    if value is not None and ts is None:
        warnings.append(f"line {number}: unparseable timestamp {shown(value)}")
    return ts


def argv_command(argv: object) -> str | None:
    """A command given as a list of words, as one shell line: the script of `bash -lc SCRIPT` (or sh, zsh, dash, ash,
    ksh with -c or -lc), which is what the shell runs, else the words joined with shell quoting. None unless argv is a
    non-empty list of strings."""
    if not isinstance(argv, list) or not argv or not all(isinstance(word, str) for word in argv):
        return None
    if len(argv) == 3 and os.path.basename(argv[0].replace("\\", "/")) in _SHELLS and argv[1] in _SHELL_FLAGS:
        return argv[2]
    return shlex.join(argv)


def tool_text(name: object, arguments: object, command: object = None) -> str:
    """A tool call as line text: command bare when the call is a shell tool's and command is a string, so the rules
    read it as typed; otherwise "name: <arguments as JSON>", as the generic agent log reader writes a structured call.
    A string argument is written as a JSON string too, so a patch or a file's content stays one quoted value that is
    never split into commands."""
    if isinstance(command, str):
        return command
    label = name if isinstance(name, str) and name else "tool"
    return f"{label}: {json.dumps(arguments, ensure_ascii=False) if isinstance(arguments, str) else as_text(arguments)}"


def parsed_arguments(value: object) -> object:
    """A tool call's arguments: a JSON string parsed (OpenAI and Codex send them as text), anything else as it is.
    Text that is not JSON stays text."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, RecursionError):
            return value
    return value


def block_texts(content: object, types: frozenset[str]) -> list[str]:
    """The texts of a message's content: a string, or the "text" of each block whose type is in types. Other blocks
    (images, documents) give nothing."""
    if isinstance(content, str):
        return [content]
    if not isinstance(content, list):
        return []
    return [block["text"] for block in content
            if isinstance(block, dict) and block.get("type") in types and isinstance(block.get("text"), str)]


def joined_lines(lines: list[str], first: int) -> RawCommand:
    """Physical lines that make one record (from line first on), joined with newlines, with where each later line
    starts recorded (RawCommand.line_starts), so each split part keeps its own file line."""
    starts, size = [], 0
    for line in lines[:-1]:
        size += len(line) + 1
        starts.append(size)
    return RawCommand(line=first, text="\n".join(lines), line_starts=tuple(starts) if starts else None)
