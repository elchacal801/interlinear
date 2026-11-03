"""Codex CLI logs: session rollouts (~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl) and the prompt history
(~/.codex/history.jsonl), one JSON record per line.

A rollout record has a "timestamp", a "type" and a "payload". The conversation is in response_item records, whose
payload is an OpenAI Responses API item: a message (user, assistant, developer or system), reasoning, a tool call
(function_call, custom_tool_call, local_shell_call, web_search_call) or a tool call's output. Older rollouts hold the
items themselves, one per line, without the wrapper. event_msg records repeat what the items hold for the terminal
interface, and session_meta, turn_context and compacted records are Codex's own bookkeeping: none of them gives a
line. A prompt history record holds a session_id, a "ts" in epoch seconds and the prompt in "text".

Actors: operator for what the person typed; agent_reasoning for the model's text and reasoning summaries; agent_tool
for each tool call, a shell call as its bare command so the rules read it as typed; tool_output for tool output and
for the instructions and context Codex itself puts in the conversation (developer and system messages, and user
messages that are its environment or AGENTS.md wrappers), which is never glossed.
"""

from __future__ import annotations

import re

from . import RawCommand
from .records import (CONFIG_NOTE, argv_command, as_text, block_texts, epoch_ts, iso_ts, is_operator_config,
                      json_records, kept_whole, parsed_arguments, read_safely, record_text, shown, tool_text)

BOOKKEEPING = frozenset(("session_meta", "turn_context", "event_msg", "compacted"))
ITEM_TYPES = frozenset(("message", "reasoning", "function_call", "function_call_output", "custom_tool_call",
                        "custom_tool_call_output", "local_shell_call", "web_search_call"))
_TEXT = frozenset(("input_text", "output_text", "text"))
# User messages Codex writes itself: the environment, AGENTS.md and permission instructions.
_HARNESS = re.compile(r"\s*(?:<(?:environment_context|user_instructions|permissions[ _]instructions|turn_aborted|"
                      r"user_shell_command)\b|# AGENTS\.md instructions)")


def shell_command(name: object, arguments: object) -> str | None:
    """The command a Codex shell tool runs, or None for any other call: shell and container.exec take an argument
    vector in "command", shell_command a string in "command", exec_command a string in "cmd"."""
    if not isinstance(arguments, dict) or not isinstance(name, str):
        return None
    if name in ("shell", "container.exec", "local_shell"):
        return argv_command(arguments.get("command"))
    if name == "shell_command" and isinstance(arguments.get("command"), str):
        return arguments["command"]
    if name == "exec_command" and isinstance(arguments.get("cmd"), str):
        return arguments["cmd"]
    return None


def _output_text(output: object) -> str:
    """A tool output: Codex stores a shell call's as a JSON string {"output": ..., "metadata": ...}."""
    if isinstance(output, str):
        parsed = parsed_arguments(output)
        if isinstance(parsed, dict) and isinstance(parsed.get("output"), str):
            return parsed["output"]
        return output
    return "" if output is None else as_text(output)


def read_item(item: dict, number: int, ts: str | None, out: list[RawCommand], warnings: list[str]) -> None:
    """One Responses API item as lines. Hermes request dumps sent to a Responses endpoint hold the same items."""
    kind = item.get("type")
    if kind == "message":
        role = item.get("role")
        for text in block_texts(item.get("content"), _TEXT):
            if role == "user":
                actor = "tool_output" if _HARNESS.match(text) else "operator"
            elif role == "assistant":
                actor = "agent_reasoning"
            elif role in ("developer", "system"):
                actor = "tool_output"
            else:
                out.append(kept_whole(number, record_text(item), warnings, f"message role {shown(role)} not read"))
                return
            out.append(RawCommand(line=number, text=text, ts=ts, actor=actor))
    elif kind == "reasoning":
        for key in ("summary", "content"):  # encrypted_content cannot be read
            for text in block_texts(item.get(key), frozenset(("summary_text", "reasoning_text", "text"))):
                if text.strip():
                    out.append(RawCommand(line=number, text=text, ts=ts, actor="agent_reasoning"))
    elif kind == "function_call":
        name, arguments = item.get("name"), parsed_arguments(item.get("arguments"))
        out.append(RawCommand(line=number, text=tool_text(name, arguments, shell_command(name, arguments)), ts=ts,
                              actor="agent_tool"))
    elif kind == "local_shell_call":
        action = item.get("action")
        command = argv_command(action.get("command")) if isinstance(action, dict) else None
        out.append(RawCommand(line=number, text=tool_text("local_shell", action, command), ts=ts, actor="agent_tool"))
    elif kind == "custom_tool_call":  # a freeform tool such as apply_patch: its input is one string
        out.append(RawCommand(line=number, text=tool_text(item.get("name"), item.get("input")), ts=ts,
                              actor="agent_tool"))
    elif kind == "web_search_call":
        out.append(RawCommand(line=number, text=tool_text("web_search", item.get("action")), ts=ts,
                              actor="agent_tool"))
    elif kind in ("function_call_output", "custom_tool_call_output"):
        out.append(RawCommand(line=number, text=_output_text(item.get("output")), ts=ts, actor="tool_output"))
    else:
        out.append(kept_whole(number, record_text(item), warnings, f"item type {shown(kind)} not read"))


def _record(record: dict, number: int, line: str, out: list[RawCommand], warnings: list[str]) -> None:
    kind = record.get("type")
    if kind is None and isinstance(record.get("text"), str) and "session_id" in record:
        out.append(RawCommand(line=number, text=record["text"], ts=epoch_ts(record.get("ts"), number, warnings),
                              actor="operator"))
        return
    if not isinstance(kind, str):
        if "record_type" in record or "instructions" in record:  # an older rollout's state or first line
            return
        out.append(kept_whole(number, line, warnings, f"record type is {shown(kind)}"))
        return
    if kind in BOOKKEEPING:
        return
    ts = iso_ts(record.get("timestamp"), number, warnings)
    if kind == "response_item":
        payload = record.get("payload")
        if isinstance(payload, dict):
            read_item(payload, number, ts, out, warnings)
        else:
            out.append(kept_whole(number, line, warnings, "response_item has no payload object"))
    elif kind in ITEM_TYPES:  # an older rollout: the item itself
        read_item(record, number, ts, out, warnings)
    else:
        out.append(kept_whole(number, line, warnings, f"record type {shown(kind)} not read"))


def read_codex(text: str) -> tuple[list[RawCommand], list[str]]:
    """Read a Codex rollout or prompt history. A line no rule covers is kept whole as unknown."""
    out: list[RawCommand] = []
    warnings: list[str] = []
    for number, line, record in json_records(text):
        if is_operator_config(record):
            warnings.append(f"line {number}: {CONFIG_NOTE}")
            continue
        if not isinstance(record, dict):
            out.append(kept_whole(number, line, warnings, "not a JSON object" if record is not None else "not JSON"))
            continue
        read_safely(_record, record, number, line, out, warnings)
    return out, warnings
