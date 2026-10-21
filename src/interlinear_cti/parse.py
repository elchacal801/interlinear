"""Stage 1: turn raw transcript files into transcript.json. Standard library only; never executes input.

Every file and folder it is given is hostile, so one bad entry is recorded and skipped, never allowed to stop the run:
- folders are walked without following symlinks or junctions, and only regular files are opened, so a link cannot
  reach outside the input and a FIFO or a device cannot block the run;
- each file's bytes, and each run's files, lines and kept line text, are capped, so memory stays bounded by the caps;
- every string that reaches the transcript or the console is defanged and has its control characters escaped.
"""

from __future__ import annotations

import bisect
import codecs
import datetime as _dt
import functools
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path

from . import __version__, decode
from .fileio import atomic_write
from .normalize import defang, has_unusual_characters, normalize_text, split_command_spans
from .readers import RawCommand, split_lines
from .readers.agent_log import read_agent_jsonl
from .readers.script import read_script, split_powershell_statements
from .readers.shell_history import read_bash, read_powershell, read_zsh, unmetafy
from .textshow import is_hidden, show_controls

KINDS = ("auto", "bash", "zsh", "powershell", "script", "agent-jsonl")
SOURCE_KIND = {"bash": "bash_history", "zsh": "zsh_history", "powershell": "powershell_history",
               "script": "script", "agent-jsonl": "agent_jsonl", "unknown": "unknown"}
SPLIT_ACTORS = {"operator", "agent_tool", "unknown"}
MAX_FILE_BYTES = 8 * 1024 * 1024  # a larger file is hashed by streaming it, and not parsed
MAX_LINES = 500_000  # transcript lines per run; the rest of the run is recorded by hash only
MAX_RETAINED_BYTES = 256 * 1024 * 1024  # the run's line text, by sys.getsizeof; the rest is recorded by hash only
MAX_FILES = 100_000  # files recorded per run; any more are only counted
MAX_READER_WARNINGS = 100  # a file's reader warnings kept; the rest are counted in one warning
MAX_DECODED_LINES = 64  # child lines decoded from one command's payloads, at every depth together
_PARENT = "_parent"  # a decoded line's parent line, held until the run's lines are numbered
MAX_WARNINGS = 10_000  # a run's warnings kept; the rest are counted in one final warning
# Folders deeper than this are not walked. os.walk recurses on Python 3.10 and 3.11 and raises RecursionError near
# 1,000 levels; this leaves room below that for the caller's stack, and makes every supported Python walk the same.
MAX_DEPTH = 512
_CHUNK = 1024 * 1024
_AGENT_CHUNK = 64 * 1024  # characters of an agent log given to its reader at a time, rounded up to a whole line
_UNDECODABLE_SHARE = 0.05  # binary when more than this share of the decoded characters came from undecodable input
_UNDECODABLE_FLOOR = 32  # and more than this many did, so a short file with a few bad bytes stays text
_NOT_TEXT = frozenset(("Cn", "Co", "Cs"))  # unassigned, private use and surrogate code points
_CONTROL_OK = {8, 9, 10, 12, 13, 27}
_REPLACEMENT = chr(0xFFFD)
_REPLACEMENT_UTF8 = _REPLACEMENT.encode("utf-8")
_UTF16_BOMS = (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)
# Never follow a symlink swapped in after the lstat check, never block on a FIFO swapped in, and read bytes
# untranslated on Windows.
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
_SYMLINK = "symlink, not followed"
_NOT_REGULAR = "not a regular file"
# Invisible characters: C0 controls, DEL and C1 controls, which a terminal may act on (ESC and CSI sequences, OSC 52
# clipboard writes), and the hidden characters of textshow.is_hidden (format characters, such as bidi controls,
# zero-width characters and the tag characters U+E0000 to U+E007F; U+2028 and U+2029; the default-ignorable characters
# outside Cf, such as variation selectors and Hangul fillers; and U+2800), which hide or change text. A tag character
# spells text a model reads and an analyst never sees. Built with chr() so this file stays ASCII.
_BACKSLASH = chr(0x5C)
# Names and warnings write each one as an escape: \xNN for a control, and for the rest a backslash, u and four hex
# digits, or a backslash, U and eight. A backslash that already reads as one of these escapes is written as \x5c, so
# every escape in the result is one. The candidates are every character outside printable ASCII, and such a backslash.
_ESCAPE_CANDIDATES = re.compile("[^" + chr(0x20) + "-" + chr(0x7E) + "]|" + re.escape(_BACKSLASH)
                                + "(?=x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})")
# Line text shows each one with textshow.show_controls, which the bash joiner also uses to check a record's length.
_WARNING_LINE = re.compile("line ([0-9]+):")  # how every agent log reader warning starts
# A command line that holds a blank other than space and tab, or a control character (normalize.has_unusual_characters)
# may read differently to bash than it looks, so the rules leave it to the model (rules.Library.match), and parse says so.
UNUSUAL_NOTE = "a blank other than space or tab, or a control character; left to the model"
# A file or agent session that holds a NUL, a CR or any other C0 or C1 control (or DEL) but tab and newline gets no
# context label at all (Source.no_context): bash drops a NUL and keeps a CR that the readers drop at a line's end, so
# a backslash before either joins lines differently than the stored lines show. The file is still read. A PowerShell
# source whose line endings are uniformly CRLF is the exception (_uniform_crlf_to_lf): PowerShell reads CRLF as LF.
NO_CONTEXT_NOTE = "a NUL, CR or other control character; no line of this file is labeled context"
_RAW_CONTROL = re.compile("[" + chr(0) + "-" + chr(8) + chr(11) + "-" + chr(31) + chr(127) + "-" + chr(159) + "]")
# The same controls as line text shows them (textshow.show_controls): a control picture for a C0 control or DEL, and
# U+27E8, U+00NN, U+27E9 for a C1 control.
_SHOWN_CONTROL = re.compile("[" + chr(0x2400) + "-" + chr(0x2421) + "]|" + chr(0x27E8) + "U[+]00[89][0-9A-F]"
                            + chr(0x27E9))


def _uniform_crlf_to_lf(text: str) -> str:
    """A PowerShell source's text with CRLF line endings made LF, when every line ending is CRLF: every LF follows a
    CR and every CR comes before an LF. Windows writes PowerShell scripts and the PSReadLine history that way, and
    PowerShell reads CRLF as LF, so the CRs are not a taint there. Any other CR (a lone CR, a CR before a CR, or a
    file that mixes CRLF and LF) leaves the text unchanged, so the default deny still applies. Only PowerShell
    sources come here: a CR is a bash concern, so bash, zsh and sh sources keep the strict rule."""
    crlf = text.count("\r\n")
    if crlf and crlf == text.count("\n") == text.count("\r"):
        return text.replace("\r\n", "\n")
    return text


def _glossed_by_rules(actor: str, detected: str) -> bool:
    """Whether the rules read a line of this actor from a file of this kind, as glossing does: in an agent log only
    the tool calls (its operator lines are chat), elsewhere every line."""
    return actor == "agent_tool" if detected == "agent-jsonl" else actor in ("operator", "unknown")


class _NotRegularFile(Exception):
    """The entry was no longer a regular file when it was opened."""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@functools.lru_cache(maxsize=4096)
def _escape_form(ch: str) -> str:
    code = ord(ch)
    if code < 0x20 or 0x7F <= code <= 0x9F or code == 0x5C:
        return f"{_BACKSLASH}x{code:02x}"
    if is_hidden(ch):
        return f"{_BACKSLASH}u{code:04x}" if code <= 0xFFFF else f"{_BACKSLASH}U{code:08x}"
    return ch


def escape_controls(text: str, keep: str = "\n\t") -> str:
    r"""Write each invisible character as an escape, for names and warnings: \xNN for a C0 control, DEL or a C1
    control, and for a hidden character (textshow.is_hidden) a backslash, u and four hex digits, or a backslash, U
    and eight.

    The characters in keep stay as they are. A backslash that already reads as one of these escapes becomes \x5c, so
    every escape in the result is one, and the original can be read back exactly.
    """
    return _ESCAPE_CANDIDATES.sub(lambda m: m.group() if m.group() in keep else _escape_form(m.group()), text)


def is_binary(data: bytes) -> bool:
    """Whether more than a tenth of the first 8 KiB are control characters other than backspace, tab, newline, form
    feed, carriage return and escape (a NUL counts as one).

    A NUL alone does not make a file binary: bash file refuses a script with one in its first line (or its first two,
    after #!), but bash < file, source, dash and sh run any such script, and bash drops each NUL from a line it reads.
    So a few NULs in otherwise text keep the file text, and each record that holds one goes to the model with a
    warning (normalize.has_unusual_characters). The decode check in _decode backs this one up.
    """
    sample = data[:8192]
    if not sample:
        return False
    control = sum(1 for b in sample if b < 32 and b not in _CONTROL_OK)
    return control / len(sample) > 0.10


def detect_kind(name: str, text: str) -> str:
    """The reader for a file: by its name, then by its first non-blank line. The text must not start with a BOM."""
    base = os.path.basename(name).lower()
    # Collected files are often renamed with a host or user prefix, such as web01.bash_history.
    if base in (".zsh_history", "zsh_history", ".histfile") or base.endswith(".zsh_history"):
        return "zsh"
    if base in (".bash_history", "bash_history", ".sh_history", ".ash_history") or base.endswith(".bash_history"):
        return "bash"
    if base.endswith("consolehost_history.txt"):
        return "powershell"
    if base.endswith((".sh", ".bash", ".ps1")):
        return "script"
    if base.endswith((".jsonl", ".ndjson")):
        # Whatever the first line holds (a banner, or a record cut mid-write), so tool output is never glossed.
        return "agent-jsonl"
    first = next((line for line in split_lines(text) if line.strip()), "")
    if first.lstrip().startswith("{"):
        try:
            if isinstance(json.loads(first), dict):
                return "agent-jsonl"
        except (ValueError, RecursionError):
            pass
    if re.match(r"^: [0-9]{9,11}:[0-9]+;", first):
        return "zsh"
    if re.match(r"^#[0-9]{9,11}$", first.strip()):
        return "bash"
    return "unknown"


def read_by_kind(kind: str, name: str, text: str) -> tuple[list[RawCommand], list[str]]:
    warnings: list[str] = []
    if kind == "bash":
        return read_bash(text, warnings), warnings
    if kind == "zsh":
        return read_zsh(text), []
    if kind == "powershell":
        return read_powershell(text), []
    if kind == "script":
        return read_script(text, powershell=name.lower().endswith(".ps1"), warnings=warnings), warnings
    if kind == "agent-jsonl":
        return read_agent_jsonl(text)
    lines = [RawCommand(line=n, text=line, actor="unknown")
             for n, line in enumerate(split_lines(text), start=1) if line.strip()]
    return lines, ["unrecognized format; lines kept as unknown"]


def _read_in_chunks(kind: str, name: str, text: str):
    """Yield a file's (commands, reader warnings), in one piece, or for an agent log a chunk of whole lines at a time.

    An agent log's lines are independent records, so reading it in chunks gives the same records, with the line
    numbers in commands and warnings moved back to the file's. It bounds what the reader holds at once, and lets the
    caller stop reading at a run limit.
    """
    if kind != "agent-jsonl":
        yield read_by_kind(kind, name, text)
        return
    start = offset = 0
    while start < len(text):
        end = text.find("\n", start + _AGENT_CHUNK)
        end = len(text) if end < 0 else end + 1
        chunk = text[start:end]
        commands, warnings = read_by_kind(kind, name, chunk)
        if offset:
            for cmd in commands:
                cmd.line += offset
            warnings = [_renumber(w, offset) for w in warnings]
        yield commands, warnings
        offset += chunk.count("\n")
        start = end


def _renumber(warning: str, offset: int) -> str:
    match = _WARNING_LINE.match(warning)
    return f"line {int(match.group(1)) + offset}:{warning[match.end():]}" if match else warning


def _shown_starts(text: str, starts: tuple[int, ...]) -> tuple[int, ...]:
    """starts, offsets into text, moved to where they fall in show_controls(text), which writes a C1 control or a
    hidden character as several characters. ASCII keeps its length (a control becomes one control picture), and any
    other text is shown once, piece by piece, so this is linear."""
    if text.isascii():
        return starts
    moved, last, size = [], 0, 0
    for offset in starts:
        size += len(show_controls(text[last:offset]))
        last = offset
        moved.append(size)
    return tuple(moved)


def _sent_offsets(text: str, shown: list[int]) -> list[int]:
    """shown, ascending offsets into show_controls(text), moved back to where they fall in text: _shown_starts the
    other way. show_controls writes each character on its own, so one pass over text's characters is enough."""
    if text.isascii() and text.isprintable():
        return shown
    out, i, size = [], 0, 0
    for offset in shown:
        while size < offset:
            size += len(show_controls(text[i]))
            i += 1
        out.append(i)
    return out


def retained_size(line: dict) -> int:
    """The size, by sys.getsizeof, of the text a transcript line keeps: its text, and a split call's whole command."""
    command = (line.get("part") or {}).get("command")
    return sys.getsizeof(line["text"]) + (sys.getsizeof(command) if command is not None else 0)


def iter_lines(commands: list[RawCommand], sid: int, powershell: bool = False, physical: bool = True):
    """Show controls, split, normalize and wrap a file's commands as transcript lines (numbered later), one at a time.

    Control characters are shown first (show_controls), with characters that neither splitter reads as a separator
    or a comment, so the splitting is unchanged, and normalizing last lets its truncation bound the stored length.
    PowerShell statements are split with PowerShell's rules, since bash's misread its backtick escapes.

    Every part of a command keeps the command's actor and timestamp. A bash reader's command records where each of its
    physical lines starts (RawCommand.line_starts), since a continuation or a line-end operator joins lines with a
    space, and a part's line is the one its first character is on. Otherwise, when the newlines in a command are the
    file's own (physical, as in a zsh or PowerShell history), a part's line is the command's first line plus the
    newlines before the part. In an agent log they are inside one JSON record, so every part keeps the record's line,
    and an agent tool call split into more than one part also gives each its place in the call (model.Part): its
    index, the number of parts, where it starts in the command as sent, and on the first part the whole command.
    """
    for cmd in commands:
        text = show_controls(cmd.text)
        if cmd.actor not in SPLIT_ACTORS:
            spans = [(0, text)]
        elif powershell:
            spans = [(0, part) for part in split_powershell_statements(text)]
        else:
            spans = split_command_spans(text)
        # A part of other whitespace, such as a no-break space, is a command to bash, so only these blanks are dropped.
        spans = [(start, part) for start, part in spans if part.strip(" \t\n")]
        call = not physical and cmd.actor == "agent_tool" and len(spans) > 1
        offsets = _sent_offsets(cmd.text, [start for start, _ in spans]) if call else []
        starts = None if cmd.line_starts is None else _shown_starts(cmd.text, cmd.line_starts)
        newlines = counted = 0
        for k, (start, part) in enumerate(spans):
            if starts is not None:
                line = cmd.line + bisect.bisect_right(starts, start)
            else:
                if physical:
                    newlines += text.count("\n", counted, start)
                    counted = start
                line = cmd.line + newlines
            gloss: dict = {"source": "pending"}
            if cmd.actor == "tool_output":
                gloss = {"source": "none", "meaning": "Tool output (not glossed).", "by": f"interlinear {__version__}"}
            out = {"n": 0, "source": sid, "line": line, "ts": cmd.ts, "actor": cmd.actor,
                   "text": normalize_text(part), "gloss": gloss, "history": []}
            if call:
                out["part"] = {"index": k + 1, "of": len(spans), "offset": offsets[k]}
                if k == 0:
                    out["part"]["command"] = normalize_text(text)
            yield out
            if cmd.actor in SPLIT_ACTORS:
                yield from _decoded_lines(part, out, powershell, depth=1, budget=[MAX_DECODED_LINES])


def _decoded_lines(text: str, parent: dict, powershell: bool, depth: int, budget: list[int]):
    """The child lines of the payloads that one command's text holds (decode.payloads), decoded as plain data and
    never run: at most decode.MAX_PAYLOADS payloads per command, decode.MAX_DEPTH levels of payloads inside payloads,
    and budget[0] lines for the whole top-level command. Each child keeps its parent's source, line, timestamp and
    actor, and its decoded entry names its encoding, depth, and the payload's SHA-256 and length; the parent's n is
    set once the run's lines are numbered (_link_decoded). Its text is shown, split and normalized as a line's is."""
    decoded = 0
    for token, encoding in decode.payloads(text):
        if decoded >= decode.MAX_PAYLOADS or budget[0] <= 0:
            return
        found = decode.decode_payload(token, encoding)
        if found is None:
            continue
        decoded += 1
        plain, encoding, truncated = found
        shown = show_controls(plain)
        in_powershell = powershell or encoding == decode.UTF16
        parts = split_powershell_statements(shown) if in_powershell else [p for _, p in split_command_spans(shown)]
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        for piece in parts:
            if not piece.strip(" \t\n"):
                continue
            if budget[0] <= 0:
                return
            budget[0] -= 1
            child = {"n": 0, "source": parent["source"], "line": parent["line"], "ts": parent["ts"],
                     "actor": parent["actor"], "text": normalize_text(piece), "gloss": {"source": "pending"},
                     "history": [], "decoded": {"parent": 0, "depth": depth, "encoding": encoding, "sha256": digest,
                                                "length": len(token), "truncated": truncated},
                     _PARENT: parent}
            yield child
            if depth < decode.MAX_DEPTH:
                yield from _decoded_lines(piece, child, in_powershell, depth + 1, budget)


def _link_decoded(lines: list[dict]) -> None:
    """Set each decoded line's parent to its parent line's n, once every line is numbered."""
    for line in lines:
        parent = line.pop(_PARENT, None)
        if parent is not None:
            line["decoded"]["parent"] = parent["n"]


def to_lines(commands: list[RawCommand], sid: int, powershell: bool = False, physical: bool = True) -> list[dict]:
    """Split, normalize and wrap one file's commands as transcript lines, numbered from 1."""
    lines = list(iter_lines(commands, sid, powershell, physical))
    for n, line in enumerate(lines, start=1):
        line["n"] = n
    _link_decoded(lines)
    return lines


def _drain(items: list):
    """Yield a list's items in order, removing each from the list, so each can be freed as soon as it is used."""
    items.reverse()
    while items:
        yield items.pop()


def _is_link(info: os.stat_result) -> bool:
    """A symlink, or on Windows any reparse point, such as a junction: never followed."""
    attributes = getattr(info, "st_file_attributes", 0)  # Windows only
    return stat.S_ISLNK(info.st_mode) or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _normalize_name(name: str) -> str:
    """Normalize a / separated name one part at a time, so a long path is not hashed as one blob.

    The joined name is defanged again, for a URL that only the joined path spells, such as http:/evil.example.
    """
    return defang("/".join(normalize_text(part) for part in name.split("/")))


def _relative(path: str, root: str) -> str:
    """A path that os.walk built under root, relative to root, with / separators."""
    rel = path[len(root):].lstrip(os.sep + (os.altsep or ""))
    return rel if os.sep == "/" else rel.replace(os.sep, "/")


def _folder_name(rel: str, root: str) -> str:
    return _normalize_name(rel or os.path.basename(os.path.normpath(root)) or root)


def _walk(root: str, warn):
    """Yield (path, name) for each entry in the folder root and below, in name order, never following a link.

    name is the path relative to root, with / separators. A folder's entries come before its subfolders' entries.
    Anything that is not a folder, a symlink or junction to one included, is yielded and never walked into. A folder
    that cannot be listed, and subfolders deeper than MAX_DEPTH, are reported through warn.
    """

    def cannot_list(exc: OSError) -> None:
        where = exc.filename if isinstance(exc.filename, str) and exc.filename.startswith(root) else root
        warn(f"{_folder_name(_relative(where, root), root)}: cannot list ({type(exc).__name__})")

    for folder, subfolders, files in os.walk(root, followlinks=False, onerror=cannot_list):
        rel = _relative(folder, root)
        walk_into, entries = [], list(files)
        for name in subfolders:
            try:
                info = os.lstat(os.path.join(folder, name))
                is_folder = stat.S_ISDIR(info.st_mode) and not _is_link(info)
            except OSError:
                is_folder = True  # os.walk then tries it, and reports it as a folder that cannot be listed
            (walk_into if is_folder else entries).append(name)
        depth = rel.count("/") + 1 if rel else 0
        if walk_into and depth >= MAX_DEPTH:
            warn(f"{_folder_name(rel, root)}: subfolders not walked; deeper than {MAX_DEPTH} levels")
            walk_into = []
        subfolders[:] = sorted(walk_into)
        for name in sorted(entries):
            yield os.path.join(folder, name), f"{rel}/{name}" if rel else name


def _entries(paths: list[str | Path], warn):
    """Yield (path, name, lstat result or None) for each input: each file argument, and what walking each folder finds.

    A file argument keeps its base name. A missing or unreadable argument raises OSError: that is invalid input.
    """
    for given in paths:
        path = os.fspath(given)
        info = os.lstat(path)
        if stat.S_ISDIR(info.st_mode) and not _is_link(info):
            for found, name in _walk(path, warn):
                yield found, name, None
        else:
            yield path, os.path.basename(path), info


def _read(path: str, limit: int) -> tuple[bytes | None, str, int]:
    """Read a regular file. Returns (data, sha256, size), where data is None if the file is larger than limit.

    The file is read and hashed in 1 MiB chunks, so a file over the limit is hashed without ever being held whole.
    """
    fd = os.open(path, _OPEN_FLAGS)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _NotRegularFile
        digest = hashlib.sha256()
        chunks: list[bytes] | None = []
        size = 0
        while chunk := os.read(fd, _CHUNK):
            digest.update(chunk)
            size += len(chunk)
            if chunks is not None:
                if size > limit:
                    chunks = None  # too large: keep hashing, but hold nothing
                else:
                    chunks.append(chunk)
        return (None if chunks is None else b"".join(chunks)), digest.hexdigest(), size
    finally:
        os.close(fd)


def _unlike_text(text: str) -> int:
    """How many characters are unassigned (Cn), private use (Co), surrogates (Cs) or U+FFFD."""
    if text.isascii():
        return 0
    category = unicodedata.category
    return sum(1 for ch in text if ch == _REPLACEMENT or category(ch) in _NOT_TEXT)


def _decode(data: bytes, name: str, kind: str) -> tuple[str, str, int] | None:
    """Decode a file and choose its reader. Returns (text, kind, undecodable count), or None if the file is binary.

    A UTF-16 BOM selects UTF-16 and skips the byte checks, which its NUL bytes would fail (Windows PowerShell 5.1's
    > writes UTF-16). Anything else must pass them, and is read as UTF-8 without any BOM. Then a file is binary when
    more than 5% of its decoded characters, and more than 32 of them, came from undecodable input. Only real decode
    errors count: a U+FFFD that was valid in the input does not. UTF-16 decodes almost any bytes, so there the count
    is of characters text does not hold: unassigned, private use and surrogate code points, and U+FFFD.
    """
    if data.startswith(_UTF16_BOMS):
        codec = "utf-16"
    elif is_binary(data):
        return None
    else:
        codec = "utf-8-sig"
    text = data.decode(codec, errors="replace")
    detected = detect_kind(name, text) if kind == "auto" else kind
    if detected == "zsh" and codec != "utf-16":
        # zsh writes its history metafied (Src/hist.c); undo that before decoding, or non-ASCII text is corrupted.
        data = unmetafy(data)
        text = data.decode(codec, errors="replace")
    if codec == "utf-16":
        valid = data.decode(codec, errors="ignore").count(_REPLACEMENT)
    else:
        valid = data.count(_REPLACEMENT_UTF8)
    undecodable = text.count(_REPLACEMENT) - valid
    unlike_text = _unlike_text(text) if codec == "utf-16" else undecodable
    if unlike_text > _UNDECODABLE_SHARE * len(text) and unlike_text > _UNDECODABLE_FLOOR:
        return None
    return text, detected, undecodable


def parse_paths(paths: list[str | Path], kind: str = "auto", case: str | None = None, now: str | None = None,
                max_file_bytes: int = MAX_FILE_BYTES, max_lines: int = MAX_LINES,
                max_retained_bytes: int = MAX_RETAINED_BYTES, max_files: int = MAX_FILES) -> dict:
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}; choose from {', '.join(KINDS)}")
    if min(max_file_bytes, max_lines, max_retained_bytes, max_files) < 0:
        raise ValueError("the byte, line and file limits must be 0 or more")
    now = now or _now()
    sources: list[dict] = []
    lines: list[dict] = []
    warnings: list[str] = []
    line_note = f"line limit reached after {max_lines} lines"
    size_note = f"line text limit reached ({max_retained_bytes} bytes)"
    limit: str | None = None  # the note of the run limit that was reached, once one is
    retained = 0  # the size of the line text kept so far, by sys.getsizeof
    unrecorded = 0  # files past max_files, counted but not recorded
    dropped = 0  # warnings past MAX_WARNINGS, counted but not kept

    def warn(warning: str) -> None:
        nonlocal dropped
        if len(warnings) < MAX_WARNINGS:
            warnings.append(warning)
        else:
            dropped += 1

    def reject(source: dict, note: str, warning: str) -> None:
        source["rejected"] = note
        warn(warning)

    def reach_limit(source: dict, name: str, note: str) -> None:
        nonlocal limit
        source["rejected"] = note
        if limit is None:  # one warning per run, naming the file where the limit was reached, and always kept
            warnings.append(f"{name}: {note}; the rest of this file and all later files recorded by hash only")
            limit = note

    for path, display, info in _entries(paths, warn):
        if len(sources) >= max_files:
            unrecorded += 1
            continue
        sid = len(sources)
        # File names and reader warnings carry attacker-controlled text, so they are normalized like lines. Names
        # are escaped when stored; warnings are escaped once, at the end.
        name = _normalize_name(display)
        source = {"id": sid, "name": escape_controls(name, keep=""), "sha256": "", "size": 0, "kind": "unknown",
                  "agent_framework": None, "parsed_at": now, "rejected": None, "no_context": None}
        sources.append(source)
        try:
            if info is None:
                info = os.lstat(path)
            if _is_link(info):
                reject(source, _SYMLINK, f"{name}: {_SYMLINK}")
                continue
            if not stat.S_ISREG(info.st_mode):
                raise _NotRegularFile
            data, sha256, size = _read(path, max_file_bytes)
        except _NotRegularFile:
            reject(source, _NOT_REGULAR, f"{name}: {_NOT_REGULAR}; skipped")
            continue
        except OSError as exc:
            reject(source, f"unreadable: {type(exc).__name__}", f"{name}: unreadable ({type(exc).__name__}); skipped")
            continue
        source["sha256"], source["size"] = sha256, size
        if limit is not None or len(lines) >= max_lines:
            reach_limit(source, name, limit or line_note)
            continue
        if data is None:
            note = f"too large ({size} bytes; limit {max_file_bytes})"
            reject(source, note, f"{name}: {note}; recorded by hash only")
            continue
        decoded = _decode(data, display, kind)
        del data
        if decoded is None:
            reject(source, "binary file; recorded by hash only", f"{name}: binary file skipped (sha256 {sha256})")
            continue
        text, detected, undecodable = decoded
        if undecodable:
            warn(f"{name}: {undecodable} undecodable byte sequence(s) replaced")
        source["kind"] = SOURCE_KIND[detected]
        if detected == "agent-jsonl":
            source["agent_framework"] = "generic"
        base = os.path.basename(path)
        powershell = detected == "powershell" or (detected == "script" and base.lower().endswith(".ps1"))
        if powershell:
            text = _uniform_crlf_to_lf(text)
        if detected != "agent-jsonl":  # an agent log's commands are inside its JSON strings, checked line by line
            control = _RAW_CONTROL.search(text)
            if control is not None:
                source["no_context"] = f"line {text.count(chr(10), 0, control.start()) + 1}: {NO_CONTEXT_NOTE}"
                warn(f"{name}: {source['no_context']}")
        try:
            file_lines: list[dict] = []
            file_warnings: list[str] = []  # the first MAX_READER_WARNINGS of this file's reader warnings
            more_warnings = 0  # the rest, counted
            kept = 0  # the size of this file's kept line text
            cut = None
            # Lines are built one at a time, and reading stops at the first one past a limit, so the rest are never
            # read or built. Each command is dropped once its lines are built.
            for commands, chunk_warnings in _read_in_chunks(detected, base, text):
                space = MAX_READER_WARNINGS - len(file_warnings)
                file_warnings.extend(chunk_warnings[:space])
                more_warnings += max(len(chunk_warnings) - space, 0)
                del chunk_warnings
                for line in iter_lines(_drain(commands), sid, powershell, physical=detected != "agent-jsonl"):
                    cost = retained_size(line)
                    if len(lines) + len(file_lines) >= max_lines:
                        cut = line_note
                        break
                    if retained + kept + cost > max_retained_bytes:
                        cut = size_note
                        break
                    file_lines.append(line)
                    kept += cost
                    if _glossed_by_rules(line["actor"], detected) and has_unusual_characters(line["text"]):
                        if source["no_context"] is None and _SHOWN_CONTROL.search(line["text"]):
                            source["no_context"] = f"line {line['line']}: {NO_CONTEXT_NOTE}"
                            warn(f"{name}: {source['no_context']}")
                        if len(file_warnings) < MAX_READER_WARNINGS:
                            file_warnings.append(f"line {line['line']}: {UNUSUAL_NOTE}")
                        else:
                            more_warnings += 1
                del commands
                if cut is not None:
                    break
            del text
        except Exception as exc:  # Parse never crashes on bad input (spec section 10); skip the file instead.
            # Only the exception's type is reported: its message can carry attacker text.
            reject(source, f"reader error: {type(exc).__name__}",
                   f"{name}: reader error ({type(exc).__name__}); file skipped")
            continue
        for warning in file_warnings:
            warn(f"{name}: {normalize_text(warning)}")
        if more_warnings:
            warn(f"{name}: {more_warnings} more reader warnings not recorded")
        if cut is not None:
            reach_limit(source, name, cut)
        lines.extend(file_lines)
        retained += kept
    if unrecorded:  # a run limit, always kept
        warnings.append(f"file limit reached after {max_files} files; {unrecorded} more not recorded")
    if dropped:
        warnings.append(f"{dropped} more warnings not recorded")
    # Interleave by time only when more than one file produced lines and every line has a timestamp.
    if len({line["source"] for line in lines}) > 1 and all(line["ts"] for line in lines):
        lines.sort(key=lambda line: line["ts"])  # stable: equal timestamps keep file order
    for n, line in enumerate(lines, start=1):
        line["n"] = n
    _link_decoded(lines)
    # The case name comes from the command line, where a hostile file name can end up, so it is treated as a file
    # name is: normalized (defanged) and escaped.
    if case is not None:
        case = escape_controls(normalize_text(case), keep="")
    return {"interlinear_version": __version__, "rules_version": None, "case": case, "datasets": {},
            "sources": sources, "lines": lines, "warnings": [escape_controls(w, keep="") for w in warnings]}


def write_transcript(data: dict, path: str | Path) -> None:
    """Write a transcript atomically (fileio.atomic_write), streaming its JSON so it is never held whole as text."""
    atomic_write(path, json.JSONEncoder(indent=2, ensure_ascii=False).iterencode(data))
