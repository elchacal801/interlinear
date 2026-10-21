"""Readers turn one input file's text into RawCommand records. Standard library only (runs in the sandbox)."""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field

_UTC = _dt.timezone.utc
_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_UTC)
_MAX_INT_DIGITS = 4300  # Python's default int() digit limit (sys.get_int_max_str_digits) since 3.10.7

# Python 3.11 widened datetime.fromisoformat (basic format, week dates, any separator, hour-only offsets), while
# 3.10 accepts only what isoformat() writes. iso_to_utc accepts one strict form and rewrites it into the 3.10 form,
# so every supported Python reads the same strings the same way: YYYY-MM-DD, then optionally a time HH:MM[:SS] with
# an optional fraction after "." or ",", and a zone Z or +HH[:]MM after the time.
# Hours run 00 to 23 and minutes and seconds 00 to 59, in the time and the zone alike. Python 3.14's fromisoformat
# reads hour 24 as the next day's midnight where earlier versions refuse it, and every version reads a zone minute
# of 60 as one more hour, so the gate decides these itself. A leap second of 60 is refused too.
_HOUR = r"(?:[01][0-9]|2[0-3])"
_MINUTE = r"[0-5][0-9]"
_ISO_TIMESTAMP = re.compile(
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})"
    rf"(?:(?P<sep>[T ])(?P<hhmm>{_HOUR}:{_MINUTE})(?::(?P<ss>{_MINUTE})(?:[.,](?P<fraction>[0-9]+))?)?"
    rf"(?:(?P<utc>[Zz])|(?P<sign>[+-])(?P<zh>{_HOUR}):?(?P<zm>{_MINUTE}))?)?"
)


@dataclass
class RawCommand:
    """One logical line a reader gives: its first physical line (1-based), its text, timestamp and actor.

    line_starts, from the bash readers, holds where each physical line after the first starts in text, in order: a
    continuation or a line-end operator joins lines with a space, so newlines alone do not tell. The character at
    offset k is on line + bisect_right(line_starts, k). Other readers leave it None, and their newlines are the file's
    own (or, in an agent log, inside one record). It describes the text's layout, so equality ignores it.
    """

    line: int
    text: str
    ts: str | None = None
    actor: str = "operator"
    line_starts: tuple[int, ...] | None = field(default=None, compare=False)


def split_lines(text: str) -> list[str]:
    """Split text into physical lines on "\\n" only, and drop one "\\r" from the end of each line.

    str.splitlines() also breaks on characters a shell keeps inside a line (vertical tab, form feed, \\x1c to
    \\x1e, \\x85, U+2028, U+2029 and a lone \\r), so a crafted file could split one command in two. As with
    splitlines(), a final "\\n" ends the last line rather than starting an empty one.
    """
    if not text:
        return []
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def unjoined_warnings(unjoined: list[tuple[int, int, str]], offset: int = 0) -> list[str]:
    """Reader warnings for the runs of lines the bash joiner kept apart (join_logical_lines' unjoined list).

    Its line numbers count from the start of the lines it was given, so offset moves them to the file's.
    """
    out = []
    for first, last, reason in unjoined:
        first, last = first + offset, last + offset
        where = f"lines {first} to {last} kept apart" if last > first else "kept as it is"
        out.append(f"line {first}: {reason}; {where}")
    return out


def _utc_text(moment: _dt.datetime) -> str:
    """'YYYY-MM-DDTHH:MM:SSZ', built from the fields: strftime pads years below 1000 differently by platform."""
    return (f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}"
            f"T{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}Z")


def epoch_to_iso(value: str | int) -> str | None:
    """Convert Unix epoch seconds to UTC 'YYYY-MM-DDTHH:MM:SSZ'. Returns None if it cannot be converted.

    This adds a timedelta instead of calling datetime.fromtimestamp, which raises OSError on Windows (but not on
    Linux) for epochs after the year 3000, so the result is the same on every OS.
    """
    if isinstance(value, str) and len(value) > _MAX_INT_DIGITS:
        return None  # Python 3.10.0 to 3.10.6 would convert it in quadratic time; later versions refuse it
    try:
        return _utc_text(_EPOCH + _dt.timedelta(seconds=int(value)))
    except (ValueError, OverflowError, OSError):
        return None


def _as_python_310_iso(match: re.Match) -> str:
    """The timestamp _ISO_TIMESTAMP matched, as Python 3.10's fromisoformat reads it."""
    text = match["date"]
    if match["hhmm"]:
        text += match["sep"] + match["hhmm"]
        if match["ss"]:
            text += ":" + match["ss"]
        if match["fraction"]:
            text += "." + (match["fraction"] + "000000")[:6]  # 3.10 takes exactly 3 or 6 digits
        if match["utc"]:
            text += "+00:00"
        elif match["sign"]:
            text += f"{match['sign']}{match['zh']}:{match['zm']}"
    return text


def iso_to_utc(value: object) -> str | None:
    """Normalize an ISO-8601 timestamp to UTC 'YYYY-MM-DDTHH:MM:SSZ'. Returns None if it cannot be parsed."""
    if not isinstance(value, str) or not value.strip():
        return None
    match = _ISO_TIMESTAMP.fullmatch(value.strip())
    if match is None:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(_as_python_310_iso(match))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_UTC)
        return _utc_text(parsed.astimezone(_UTC))
    except (ValueError, OverflowError):  # astimezone overflows at year 1 or 9999 with an offset
        return None
