"""Sliver C2 client logs, one JSON value per line:
- the console history (~/.sliver-client/history): {"datetime": RFC 3339, "block": the command line};
- console logs (~/.sliver-client/logs/): logrus JSON records ({"level", "msg", "time"}), where a "type": "command"
  record is a command the operator ran (with the session's id, name, hostname and username when one was in use),
  and other records are the client's messages;
- console recordings (also under logs/): asciicast v2, a header {"version": 2, "width", "height", "timestamp"} and
  then [seconds since start, code, data] events, where code "o" is output and "i" is typed input.

Console commands are in Sliver's own grammar, not a shell's, so the source is a c2_console and the shell rules never
read them; they go to the model. A command's session (which implant, on which host) is not kept in the line.

An operator config ({"operator", "token", "lhost", "lport", "ca_certificate", "certificate", "private_key"}) holds
credentials, not a log: it gives no line, only a warning.
"""

from __future__ import annotations

import json

from . import RawCommand, epoch_to_iso
from .records import CONFIG_NOTE, as_text, is_operator_config, iso_ts, json_records, kept_whole, read_safely, shown


def is_cast_header(record: object) -> bool:
    return isinstance(record, dict) and record.get("version") == 2 and "width" in record and "height" in record


def is_cast_event(record: object) -> bool:
    """An asciicast event: [seconds, code, data]. A recording whose header is missing starts with one."""
    return (isinstance(record, list) and len(record) == 3 and isinstance(record[0], (int, float))
            and not isinstance(record[0], bool) and isinstance(record[1], str) and isinstance(record[2], str))


class _Stream:
    """One asciicast stream cut into lines: output ("o") at each newline, dropping a CR before it (a terminal's line
    ending), and typed input ("i") at each CR, the Enter key. A line keeps the event line and time where it started.
    Its pieces are joined once, when it ends, so a line built from many small events costs linear time."""

    def __init__(self, actor: str, end: str):
        self.actor, self.end, self.pieces, self.line, self.ts = actor, end, [], 0, None

    def add(self, data: str, number: int, ts: str | None, out: list[RawCommand]) -> None:
        parts = data.split(self.end)
        for k, piece in enumerate(parts):
            if piece:
                if not self.pieces:
                    self.line, self.ts = number, ts
                self.pieces.append(piece)
            if k < len(parts) - 1:
                self.flush(out)
                self.line, self.ts = number, ts

    def flush(self, out: list[RawCommand]) -> None:
        text = "".join(self.pieces)
        self.pieces = []
        text = text[:-1] if text.endswith("\r") else text
        if text.strip():
            out.append(RawCommand(line=self.line, text=text, ts=self.ts, actor=self.actor))


def _cast_time(start: object, offset: object) -> str | None:
    if isinstance(start, bool) or not isinstance(start, (int, float)) or start != start:
        return None
    if isinstance(offset, bool) or not isinstance(offset, (int, float)) or offset != offset:
        return None
    try:
        return epoch_to_iso(int(start + offset))
    except (OverflowError, ValueError):
        return None


def _read_cast(text: str, out: list[RawCommand], warnings: list[str]) -> None:
    """Events as lines of output and of input. A later header (recordings joined into one file) starts a new
    recording: what came before it is flushed, and its timestamp is the new start."""
    streams = {"o": _Stream("tool_output", "\n"), "i": _Stream("operator", "\r")}
    header: dict = {}
    for number, line, event in json_records(text):
        if is_cast_header(event):
            for stream in streams.values():
                stream.flush(out)
            header = event
            continue
        if is_operator_config(event):
            warnings.append(f"line {number}: {CONFIG_NOTE}")
            continue
        if not is_cast_event(event):
            out.append(kept_whole(number, line, warnings, "not an asciicast event"))
            continue
        code = event[1]
        if isinstance(code, str) and code in streams:
            streams[code].add(event[2], number, _cast_time(header.get("timestamp"), event[0]), out)
        # "m" (marker) and "r" (resize) events hold no text
    for stream in streams.values():
        stream.flush(out)
    out.sort(key=lambda command: command.line)  # stable: input and output in the order the recording holds them


def _record(record: dict, number: int, line: str, out: list[RawCommand], warnings: list[str]) -> None:
    if "block" in record and "datetime" in record:
        block = record["block"]
        if isinstance(block, str):
            out.append(RawCommand(line=number, text=block, ts=iso_ts(record["datetime"], number, warnings),
                                  actor="operator"))
        else:
            out.append(kept_whole(number, line, warnings, "history block is not text"))
    elif "msg" in record and ("level" in record or "time" in record):
        command = record.get("type") == "command"
        out.append(RawCommand(line=number, text=as_text(record["msg"]), ts=iso_ts(record.get("time"), number, warnings),
                              actor="operator" if command else "tool_output"))
    else:
        out.append(kept_whole(number, line, warnings, f"record with type {shown(record.get('type'))} not read"))


def read_sliver(text: str) -> tuple[list[RawCommand], list[str]]:
    """Read a Sliver console history, console log or console recording, chosen by the file's first JSON value."""
    out: list[RawCommand] = []
    warnings: list[str] = []
    if text.lstrip().startswith("{"):  # a config written over several lines is one JSON document
        try:
            if is_operator_config(json.loads(text)):
                return [], [f"line 1: {CONFIG_NOTE}"]
        except (ValueError, RecursionError):
            pass
    first = next(((number, record) for number, _, record in json_records(text) if record is not None), None)
    if first is not None and is_operator_config(first[1]):
        return [], [f"line {first[0]}: {CONFIG_NOTE}"]
    if first is not None and (is_cast_header(first[1]) or is_cast_event(first[1])):
        _read_cast(text, out, warnings)  # without a header, events have no start time, so lines have none
        return out, warnings
    for number, line, record in json_records(text):
        if is_operator_config(record):
            warnings.append(f"line {number}: {CONFIG_NOTE}")
        elif isinstance(record, dict):
            read_safely(_record, record, number, line, out, warnings)
        else:
            out.append(kept_whole(number, line, warnings, "not a JSON object" if record is not None else "not JSON"))
    return out, warnings

