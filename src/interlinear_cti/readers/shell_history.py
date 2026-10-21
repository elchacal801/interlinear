"""bash, zsh and PowerShell history readers."""

from __future__ import annotations

import re

from ..normalize import join_logical_records
from . import RawCommand, epoch_to_iso, split_lines, unjoined_warnings

# Epochs are ASCII digits only, as bash (HIST_TIMESTAMP_START in lib/readline/histfile.c uses isdigit) and zsh
# (zstrtol in Src/hist.c) read them. In a str pattern, \d would also match other scripts' digits.
# A timestamp line as bash writes it: "#" and the epoch, in column 0. It marks the file as timestamped.
_BASH_TS = re.compile(r"#([0-9]{9,11})")
# Where bash starts an entry in a timestamped file: a column-0 "#" and an ASCII digit (HIST_TIMESTAMP_START). bash
# takes the leading digits as the epoch, so "#123" and "#1700000060x" start entries too (bash 5.3, `history -r`).
_BASH_ENTRY_START = re.compile(r"#([0-9]+)")
_ZSH_HEADER = re.compile(r": ([0-9]{9,11}):[0-9]+;")
# A metafied byte: Meta (0x83) and the byte after it, unless that byte is the newline that ends the line, or "*",
# which would unmetafy to a newline (zsh never metafies a newline, so "\x83*" only comes from a crafted file).
_META_PAIR = re.compile(rb"\x83([^\n*])")


def _is_bash_timestamp(line: str) -> bool:
    match = _BASH_TS.fullmatch(line.rstrip())
    return match is not None and epoch_to_iso(match.group(1)) is not None


def read_bash(text: str, warnings: list[str] | None = None) -> list[RawCommand]:
    """Read a bash history. Without timestamp lines, it is joined like a script.

    With them, each column-0 "#<digit>" line starts an entry that runs to the next one, which is how bash reads a
    timestamped file back (read_history_range in lib/readline/histfile.c: the lines after a timestamp form one
    multi-line entry; checked with bash 5.3 and `history -r`). So a continuation, heredoc or string never crosses
    into the next entry, and every line of an entry gets its timestamp. Lines before the first timestamp have none.
    Given a warnings list, the lines left unjoined are added to it.
    """
    lines = split_lines(text)
    if not any(_is_bash_timestamp(line) for line in lines):
        return _bash_entry(lines, 0, len(lines), None, warnings)
    out: list[RawCommand] = []
    start, ts = 0, None  # the current entry's first line (0-based) and its timestamp
    for index, line in enumerate(lines):
        marker = _BASH_ENTRY_START.match(line)
        if marker is None:
            continue
        out.extend(_bash_entry(lines, start, index, ts, warnings))
        ts = epoch_to_iso(marker.group(1))
        # A line holding only a convertible epoch lives on in ts. Any other marker line (text after the digits, or an
        # epoch that does not convert) stays visible as the first line of its entry, so no text is dropped.
        start = index + 1 if ts is not None and line.rstrip() == marker.group() else index
    out.extend(_bash_entry(lines, start, len(lines), ts, warnings))
    return out


def _bash_entry(lines: list[str], start: int, end: int, ts: str | None,
                warnings: list[str] | None) -> list[RawCommand]:
    """The logical lines of lines[start:end], one timestamped entry or a whole history without timestamps."""
    unjoined: list[tuple[int, int, str]] = []
    entry = [RawCommand(line=start + k, text=t, ts=ts, line_starts=starts)
             for k, t, starts in join_logical_records(lines[start:end], unjoined=unjoined)]
    if warnings is not None:
        warnings.extend(unjoined_warnings(unjoined, start))
    return entry


def read_zsh(text: str) -> list[RawCommand]:
    """Read a zsh history, plain or EXTENDED_HISTORY (": <epoch>:<elapsed>;<command>").

    zsh's readhistline (Src/hist.c) joins whatever line follows a line ending in a backslash, even one that looks
    like a header, and turns that backslash into a newline. Only then does it look for the header, at the start of
    the joined entry. An entry whose epoch does not convert keeps its command, without a timestamp.
    """
    out: list[RawCommand] = []
    lines = split_lines(text)
    parts: list[str] = []  # the current entry's lines, joined once when it ends
    for index, line in enumerate(lines):
        if line.endswith("\\") and index + 1 < len(lines):
            parts.append(line[:-1])
            continue
        parts.append(line)
        entry, ts = "\n".join(parts), None
        header = _ZSH_HEADER.match(entry)
        if header:
            entry, ts = entry[header.end():], epoch_to_iso(header.group(1))
        if entry.strip(" \t\n"):  # zsh's blanks are space and tab: any other whitespace is a command's text
            out.append(RawCommand(line=index - len(parts) + 2, text=entry, ts=ts))
        parts = []
    return out


def unmetafy(data: bytes) -> bytes:
    """Undo zsh's metafication of a history file, before it is decoded.

    zsh writes a byte 0x00 or 0x83 to 0xA2 as Meta (0x83) followed by the byte XOR 0x20 (metafy in Src/utils.c),
    and a Meta escapes whatever byte follows, even another Meta. zsh splits its history into lines before anything
    unmetafies them, so a Meta at the end of a line, before its newline or at the end of the file, stays as it is.
    So does a Meta before "*": unmetafying it would make a newline, and split one entry into two.
    """
    if b"\x83" not in data:
        return data
    return _META_PAIR.sub(lambda m: bytes([m.group(1)[0] ^ 0x20]), data)


def read_powershell(text: str) -> list[RawCommand]:
    """Read a PSReadLine history (ConsoleHost_history.txt).

    PSReadLine (PSReadLine/History.cs) saves a newline inside a command as a backtick and a newline. Reading back,
    a line ending in a backtick continues: exactly one backtick is dropped and the next line joins with a newline.
    There is no parity check (a typed continuation "`" is saved as "``") and no comment check. PSReadLine drops an
    entry still open at the end of the file; this keeps it.
    """
    out: list[RawCommand] = []
    lines = split_lines(text)
    parts: list[str] = []
    for index, line in enumerate(lines):
        continues = line.endswith("`")
        parts.append(line[:-1] if continues else line)
        if continues and index + 1 < len(lines):
            continue
        entry = "\n".join(parts).strip()
        if entry:
            out.append(RawCommand(line=index - len(parts) + 2, text=entry))
        parts = []
    return out
