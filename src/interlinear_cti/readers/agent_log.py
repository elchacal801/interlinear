"""Generic agent transcript reader: one JSON object per line with a role (spec section 6.3)."""

from __future__ import annotations

import json

from . import RawCommand, iso_to_utc, split_lines

ROLE_ACTOR = {"user": "operator", "assistant": "agent_reasoning", "tool_call": "agent_tool", "tool_result": "tool_output"}
_BODY_FIELD = {"user": "content", "assistant": "content", "tool_call": "input", "tool_result": "output"}


def _as_text(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _record_ts(record: object, number: int, warnings: list[str]) -> str | None:
    """A JSON object's "ts" in UTC, or None. Raw lines keep it too, so no record drops out of the timeline."""
    value = record.get("ts") if isinstance(record, dict) else None
    ts = iso_to_utc(value)
    if value is not None and ts is None:
        warnings.append(f"line {number}: unparseable timestamp {value!r}")
    return ts


def read_agent_jsonl(text: str) -> tuple[list[RawCommand], list[str]]:
    """Read one JSON record per line. A line that cannot be read as a role's text is kept whole."""
    out: list[RawCommand] = []
    warnings: list[str] = []
    # split_lines, not splitlines: JSON strings may hold a raw U+2028, U+2029 or \x85 (JSON.stringify writes them).
    for number, line in enumerate(split_lines(text), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):
            warnings.append(f"line {number}: not JSON; kept as an unknown line")
            out.append(RawCommand(line=number, text=line, actor="unknown"))
            continue
        role = record.get("role") if isinstance(record, dict) else None
        key = role.strip().lower() if isinstance(role, str) else None
        if key not in ROLE_ACTOR:
            warnings.append(f"line {number}: unrecognized role {role!r}; kept as an unknown line")
            out.append(RawCommand(line=number, text=line, ts=_record_ts(record, number, warnings), actor="unknown"))
            continue
        field = _BODY_FIELD[key]
        if field not in record:
            warnings.append(f"line {number}: role {key!r} has no {field!r} field; kept the raw line")
            # Tool output stays tool output, so text an attacker put in a fetched page or file is never glossed.
            actor = ROLE_ACTOR[key] if key == "tool_result" else "unknown"
            out.append(RawCommand(line=number, text=line, ts=_record_ts(record, number, warnings), actor=actor))
            continue
        body = record[field]
        if body is None or body == "":
            text_value = ""  # an empty body keeps its role; empty lines are dropped later
        else:
            text_value = _as_text(body)
            if key == "tool_call" and record.get("tool") and not isinstance(body, str):
                text_value = f"{record['tool']}: {text_value}"
        out.append(RawCommand(line=number, text=text_value, ts=_record_ts(record, number, warnings),
                              actor=ROLE_ACTOR[key]))
    return out, warnings
