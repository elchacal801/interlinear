"""Claude Code logs: project session transcripts (~/.claude/projects/*/*.jsonl) and the prompt history
(~/.claude/history.jsonl), one JSON record per line.

A session record has a "type". user and assistant records carry an Anthropic API "message" whose content is a string
or a list of blocks: text, thinking, tool_use (a tool's name and input) and tool_result. The rest are Claude Code's own
bookkeeping (titles, file snapshots, queue operations, API request copies, costs) and context it adds (attachments),
and give no line, except a queued prompt. A prompt history record has the typed prompt in "display".

Actors:
- operator: what the person typed (a user record's text, a slash command, a queued prompt, a history prompt and its
  pasted text);
- agent_reasoning: the model's text and thinking, and in a subagent's conversation (isSidechain) the prompts the main
  agent sent it;
- agent_tool: each tool call, a Bash call as its bare command so the rules read it as typed;
- tool_output: tool results, and text Claude Code itself put in the conversation (isMeta records, local command
  output, system notices, API error messages), which is never glossed.
"""

from __future__ import annotations

import re

from . import RawCommand
from .records import (CONFIG_NOTE, as_text, block_texts, epoch_ts, iso_ts, is_operator_config, json_records,
                      kept_whole, read_safely, record_text, shown, tool_text)

# Records that hold no conversation: Claude Code's bookkeeping. They give no line and no warning.
BOOKKEEPING = frozenset((
    "summary", "ai-title", "custom-title", "last-prompt", "tag", "agent-name", "mode", "pr-link",
    "file-history-snapshot", "queue-operation", "api-request", "api-request-blob", "api-request-shape", "atis-latch",
    "cost-state", "progress", "worktree-state", "content-replacement",
))
SHELL_TOOLS = frozenset(("Bash",))
_TEXT = frozenset(("text",))
# Text that Claude Code wraps in these tags is its own (command output, caveats, reminders, hook output), not typed.
_HARNESS = re.compile(r"\s*<(?:local-command-stdout|local-command-stderr|local-command-caveat|system-reminder|"
                      r"bash-stdout|bash-stderr|task-notification|user-prompt-submit-hook)>")


def _user_actor(text: str, meta: bool, sidechain: bool) -> str:
    """meta: Claude Code wrote the text (isMeta); sidechain: a subagent's conversation, or the model's own summary of
    the conversation before a compaction (isCompactSummary), which Claude Code stores as a user record."""
    if meta or _HARNESS.match(text):
        return "tool_output"
    return "agent_reasoning" if sidechain else "operator"


def _result_text(block: dict) -> str:
    content = block.get("content")
    if isinstance(content, list):
        parts = [part.get("text") if isinstance(part, dict) and part.get("type") == "text" else
                 "[image]" if isinstance(part, dict) and part.get("type") == "image" else as_text(part)
                 for part in content]
        return "\n".join(part for part in parts if isinstance(part, str))
    return "" if content is None else as_text(content)


def _user(record: dict, number: int, ts: str | None, out: list[RawCommand], warnings: list[str]) -> None:
    meta = record.get("isMeta") is True
    sidechain = record.get("isSidechain") is True or record.get("isCompactSummary") is True
    content = record["message"].get("content")
    if content is None:
        warnings.append(f"line {number}: user message has no content")
        return
    if isinstance(content, str):
        out.append(RawCommand(line=number, text=content, ts=ts, actor=_user_actor(content, meta, sidechain)))
        return
    if not isinstance(content, list):
        out.append(kept_whole(number, record_text(content), warnings, "user message content is not text or blocks"))
        return
    for block in content:
        kind = block.get("type") if isinstance(block, dict) else None
        if kind == "text" and isinstance(block.get("text"), str):
            text = block["text"]
            out.append(RawCommand(line=number, text=text, ts=ts, actor=_user_actor(text, meta, sidechain)))
        elif kind == "tool_result":
            out.append(RawCommand(line=number, text=_result_text(block), ts=ts, actor="tool_output"))
        elif kind not in ("image", "document"):
            out.append(kept_whole(number, record_text(block), warnings, f"user block type {shown(kind)} not read"))


def _assistant(record: dict, number: int, ts: str | None, out: list[RawCommand], warnings: list[str]) -> None:
    error = record.get("isApiErrorMessage") is True  # Claude Code's own message about a failed API call
    content = record["message"].get("content")
    if content is None:
        warnings.append(f"line {number}: assistant message has no content")
        return
    if isinstance(content, str):
        out.append(RawCommand(line=number, text=content, ts=ts, actor="tool_output" if error else "agent_reasoning"))
        return
    if not isinstance(content, list):
        why = "assistant message content is not text or blocks"
        out.append(kept_whole(number, record_text(content), warnings, why))
        return
    for block in content:
        kind = block.get("type") if isinstance(block, dict) else None
        if kind == "text" and isinstance(block.get("text"), str):
            out.append(RawCommand(line=number, text=block["text"], ts=ts,
                                  actor="tool_output" if error else "agent_reasoning"))
        elif kind == "thinking":
            if isinstance(block.get("thinking"), str) and block["thinking"].strip():
                out.append(RawCommand(line=number, text=block["thinking"], ts=ts, actor="agent_reasoning"))
        elif kind in ("tool_use", "server_tool_use"):
            name, arguments = block.get("name"), block.get("input")
            shell = isinstance(name, str) and name in SHELL_TOOLS and isinstance(arguments, dict)
            command = arguments.get("command") if shell else None
            out.append(RawCommand(line=number, text=tool_text(name, arguments, command), ts=ts, actor="agent_tool"))
        elif kind == "redacted_thinking":
            continue  # encrypted, nothing to read
        elif isinstance(kind, str) and kind.endswith("_tool_result"):  # a server tool's result, such as a web search
            out.append(RawCommand(line=number, text=as_text(block.get("content")), ts=ts, actor="tool_output"))
        else:
            out.append(kept_whole(number, record_text(block), warnings, f"assistant block type {shown(kind)} not read"))


def _history(record: dict, number: int, out: list[RawCommand], warnings: list[str]) -> None:
    """A prompt history record: the prompt as typed, then the text of each paste it holds, in the order stored."""
    ts = epoch_ts(record.get("timestamp"), number, warnings, per_second=1000)
    out.append(RawCommand(line=number, text=record["display"], ts=ts, actor="operator"))
    pasted = record.get("pastedContents")
    if isinstance(pasted, dict):
        for item in pasted.values():
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("content"), str):
                out.append(RawCommand(line=number, text=item["content"], ts=ts, actor="operator"))


def _record(record: dict, number: int, line: str, out: list[RawCommand], warnings: list[str]) -> None:
    kind = record.get("type")
    if kind is None and isinstance(record.get("display"), str):
        _history(record, number, out, warnings)
        return
    if not isinstance(kind, str):
        out.append(kept_whole(number, line, warnings, f"record type is {shown(kind)}"))
        return
    if kind in BOOKKEEPING:
        return
    ts = iso_ts(record.get("timestamp"), number, warnings)
    if kind in ("user", "assistant"):
        if not isinstance(record.get("message"), dict):
            out.append(kept_whole(number, line, warnings, f"{kind} record has no message object"))
        elif kind == "user":
            _user(record, number, ts, out, warnings)
        else:
            _assistant(record, number, ts, out, warnings)
    elif kind == "system":
        content = record.get("content")
        if isinstance(content, str) and content.strip():
            out.append(RawCommand(line=number, text=content, ts=ts, actor="tool_output"))
    elif kind == "attachment":
        attachment = record.get("attachment")
        if isinstance(attachment, dict) and attachment.get("type") == "queued_command":
            for prompt in block_texts(attachment.get("prompt"), _TEXT):
                out.append(RawCommand(line=number, text=prompt, ts=ts, actor="operator"))
    else:
        out.append(kept_whole(number, line, warnings, f"record type {shown(kind)} not read"))


def read_claude_code(text: str) -> tuple[list[RawCommand], list[str]]:
    """Read a Claude Code session transcript or prompt history. A line no rule covers is kept whole as unknown."""
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
