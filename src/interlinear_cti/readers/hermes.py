"""Hermes agent files under ~/.hermes, chosen by content:
- a session snapshot (sessions/session_<id>.json): a JSON document whose "messages" are OpenAI chat messages;
- a request dump (sessions/request_dump_<id>_<time>.json): the API request Hermes sent, with the conversation in
  request.body.messages (chat) or request.body.input (Responses API items, read as Codex reads them);
- a gateway transcript (sessions/<id>.jsonl): one chat message per line, and "session_meta" lines that give none;
- the state database (state.db, SQLite): its messages table (read_hermes_state);
- the logs (logs/agent.log, errors.log, gateway.log): Python logging records, which start with
  "YYYY-MM-DD HH:MM:SS,mmm "; the lines after a record's first, such as a traceback, belong to it;
- the prompt history (.hermes_history, prompt_toolkit's FileHistory): "# <time>" lines and the entry's lines after
  them, each starting with "+";
- the memories (memories/MEMORY.md and USER.md): entries the agent saved, separated by lines holding only "section"
  signs (U+00A7).

Chat messages map as in the other agent logs: user to operator, the assistant's text and reasoning to
agent_reasoning, each tool call to agent_tool (the terminal tool's command bare, so the rules read it as typed), tool
results and system or developer messages to tool_output. Log records are the agent's own output (tool_output), and
memory entries are its notes (agent_reasoning). Times in the logs and the prompt history carry no zone and are read
as UTC.
"""

from __future__ import annotations

import json
import re

from . import RawCommand, iso_to_utc, split_lines
from .codex import read_item
from .records import (CONFIG_NOTE, as_text, block_texts, epoch_ts, iso_ts, is_operator_config, joined_lines,
                      json_records, kept_whole, parsed_arguments, read_safely, record_text, shown, tool_text)

SHELL_TOOLS = frozenset(("terminal",))
SQLITE_HEADER = b"SQLite format 3" + bytes(1)
_TEXT = frozenset(("text", "input_text", "output_text"))
_SECTION = chr(0xA7)
_LOG_START = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} ")
_HISTORY_TIME = re.compile(r"# ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?)")
_WS = re.compile(r"[ \t\n\r]*")
_BRACKET_OR_QUOTE = re.compile(r'["\[\]{}]')
_SCALAR = re.compile(r"-?Infinity|NaN|true|false|null|[-+0-9.eE]+")
# The file a name says it is (a stored copy may carry a _<hex> suffix): the prompt history, a gateway transcript, a
# session snapshot or request dump, a log, or a memory file. A name that says none is decided by content.
_FORM_BY_NAME = re.compile(r"[.](jsonl|json|log|md)(?:_[0-9a-f]{8,64})?$")
_FORMS = {"jsonl": "jsonl", "json": "document", "log": "log", "md": "memory"}
# The state database is read in memory with SQLite's defensive settings, and a query stops after this many virtual
# machine steps (counted in thousands), so a crafted database cannot run for long.
_STEP_CHUNK = 1000
_MAX_STEP_CHUNKS = 200_000
_STATE_COLUMNS = ("id", "session_id", "role", "content", "tool_calls", "tool_call_id", "tool_name", "timestamp",
                  "reasoning", "reasoning_content")


def read_message(message: dict, number: int, out: list[RawCommand], warnings: list[str],
                 ts: str | None = None) -> None:
    """One OpenAI chat message as lines: content, reasoning and tool calls."""
    role = message.get("role")
    content = message.get("content")
    texts = block_texts(content, _TEXT) if content is None or isinstance(content, (str, list)) else [as_text(content)]
    texts = [text for text in texts if text.strip()]
    if role == "session_meta":
        return
    if role == "user":
        out.extend(RawCommand(line=number, text=text, ts=ts, actor="operator") for text in texts)
    elif role == "assistant":
        for key in ("reasoning", "reasoning_content"):
            if isinstance(message.get(key), str) and message[key].strip():
                out.append(RawCommand(line=number, text=message[key], ts=ts, actor="agent_reasoning"))
        out.extend(RawCommand(line=number, text=text, ts=ts, actor="agent_reasoning") for text in texts)
        calls = parsed_arguments(message.get("tool_calls"))
        for call in calls if isinstance(calls, list) else ():
            if not isinstance(call, dict):
                out.append(kept_whole(number, record_text(call), warnings, "tool call is not a JSON object"))
                continue
            function = call["function"] if isinstance(call.get("function"), dict) else call
            name, arguments = function.get("name"), parsed_arguments(function.get("arguments"))
            shell = isinstance(name, str) and name in SHELL_TOOLS and isinstance(arguments, dict)
            command = arguments.get("command") if shell else None
            out.append(RawCommand(line=number, text=tool_text(name, arguments, command), ts=ts, actor="agent_tool"))
    elif role == "tool":
        text = "\n".join(texts) if isinstance(content, list) else as_text(content) if content is not None else ""
        out.append(RawCommand(line=number, text=text, ts=ts, actor="tool_output"))
    elif role in ("system", "developer"):
        out.extend(RawCommand(line=number, text=text, ts=ts, actor="tool_output") for text in texts)
    elif role == "tool_call":  # the generic agent log's roles, as its reader maps them, should such a log come here
        arguments = message.get("input")
        text = arguments if isinstance(arguments, str) else tool_text(message.get("tool"), arguments)
        out.append(RawCommand(line=number, text=text, ts=ts, actor="agent_tool"))
    elif role == "tool_result":
        output = message.get("output")
        out.append(RawCommand(line=number, text="" if output is None else as_text(output), ts=ts, actor="tool_output"))
    else:
        out.append(kept_whole(number, record_text(message), warnings, f"message role {shown(role)} not read"))


def _message_ts(message: dict, number: int, warnings: list[str]) -> str | None:
    value = message.get("timestamp")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return epoch_ts(value, number, warnings)
    return iso_ts(value, number, warnings)


def _string_end(text: str, at: int) -> int:
    """Where the JSON string whose opening quote is at text[at] ends: at the first quote after an even run of
    backslashes. Each run is counted once, so this is linear."""
    i = at + 1
    while True:
        j = text.find('"', i)
        if j < 0:
            raise ValueError("unterminated string")
        k = j
        while k > at + 1 and text[k - 1] == "\\":
            k -= 1
        if (j - k) % 2 == 0:
            return j + 1
        i = j + 1


def _value_end(text: str, at: int) -> int:
    """Where the JSON value starting at text[at] ends, found by tracking strings and bracket depth, never by recursion:
    json.dumps, repr and the decoder can overflow the stack at depths json.loads accepts (Python 3.14 most of all)."""
    if text.startswith('"', at):
        return _string_end(text, at)
    if not text.startswith(("[", "{"), at):
        scalar = _SCALAR.match(text, at)
        if scalar is None or scalar.end() == at:
            raise ValueError("expected a value")
        return scalar.end()
    depth, i = 0, at
    while True:
        found = _BRACKET_OR_QUOTE.search(text, i)
        if found is None:
            raise ValueError("unbalanced brackets")
        i = found.start()
        if found.group() == '"':
            i = _string_end(text, i)
            continue
        depth += 1 if found.group() in "[{" else -1
        i += 1
        if depth == 0:
            return i


def _item_lines(text: str, path: tuple[str, ...]) -> list[int] | None:
    """The file line where each item of the JSON array at path (object keys from the top) starts, or None when the
    path holds no array. As json.loads does, the last of repeated keys counts. The document is valid JSON (json.loads
    read it); one pass that never recurses finds the items, so this is linear in the text and safe at any depth."""
    at = _WS.match(text, 0).end()
    for key in path:
        if not text.startswith("{", at):
            return None
        found, at = None, _WS.match(text, at + 1).end()
        while not text.startswith("}", at):
            end = _string_end(text, at)
            name = json.loads(text[at:end])
            at = _WS.match(text, _WS.match(text, end).end() + 1).end()  # past the colon
            start, at = at, _value_end(text, at)
            if name == key:
                found = start
            at = _WS.match(text, at).end()
            if text.startswith(",", at):
                at = _WS.match(text, at + 1).end()
        if found is None:
            return None
        at = found
    if not text.startswith("[", at):
        return None
    lines, line, counted = [], 1, 0
    at = _WS.match(text, at + 1).end()
    while not text.startswith("]", at):
        line += text.count("\n", counted, at)
        counted = at
        lines.append(line)
        at = _WS.match(text, _value_end(text, at)).end()
        if text.startswith(",", at):
            at = _WS.match(text, at + 1).end()
    return lines


def _read_document(text: str, document: dict, out: list[RawCommand], warnings: list[str]) -> None:
    """The messages of a session snapshot or request dump, as json.loads read them, each on the line it starts."""
    if isinstance(document.get("messages"), list):
        path: tuple[str, ...] = ("messages",)
    else:
        request = document.get("request")
        body = request.get("body") if isinstance(request, dict) else None
        if not isinstance(body, dict) or not isinstance(body.get("messages", body.get("input")), list):
            warnings.append("line 1: a JSON document that is not a Hermes session or request dump; not read")
            return
        path = ("request", "body", "messages" if isinstance(body.get("messages"), list) else "input")
    items = document
    for key in path:
        items = items[key]
    try:
        numbers = _item_lines(text, path)
    except (ValueError, RecursionError):
        numbers = None
    if numbers is None or len(numbers) != len(items):  # not expected: json.loads read the same text
        warnings.append("line 1: where each message starts was not found; every message is given line 1")
        numbers = [1] * len(items)
    for number, item in zip(numbers, items):
        if is_operator_config(item):
            warnings.append(f"line {number}: {CONFIG_NOTE}")
        elif not isinstance(item, dict):
            out.append(kept_whole(number, record_text(item), warnings, "message is not a JSON object"))
        elif item.get("type") not in (None, "message"):  # a Responses API item other than a message
            read_safely(lambda i, n, _, o, w: read_item(i, n, None, o, w), item, number, record_text(item), out,
                        warnings)
        else:
            read_safely(lambda m, n, _, o, w: read_message(m, n, o, w, _message_ts(m, n, w)), item, number,
                        record_text(item), out, warnings)


def _read_jsonl(text: str, out: list[RawCommand], warnings: list[str]) -> None:
    for number, line, record in json_records(text):
        if is_operator_config(record):
            warnings.append(f"line {number}: {CONFIG_NOTE}")
        elif not isinstance(record, dict):
            out.append(kept_whole(number, line, warnings, "not a JSON object" if record is not None else "not JSON"))
        else:
            read_safely(lambda m, n, _, o, w: read_message(m, n, o, w, _message_ts(m, n, w)), record, number, line,
                        out, warnings)


def _read_log(lines: list[str], out: list[RawCommand]) -> None:
    record: list[str] = []
    first = 0
    for number, line in enumerate(lines, start=1):
        if _LOG_START.match(line) or not record:
            if record:
                out.append(_log_record(record, first))
            record, first = [line], number
        else:
            record.append(line)
    if record:
        out.append(_log_record(record, first))


def _log_record(lines: list[str], first: int) -> RawCommand:
    last = len(lines) - 1
    while last > 0 and not lines[last].strip():  # trailing blank lines are not the record's
        last -= 1
    lines = lines[:last + 1]
    command = joined_lines(lines, first)
    command.actor = "tool_output"
    if _LOG_START.match(lines[0]):
        command.ts = iso_to_utc(lines[0][:19])
    return command


def _read_history(lines: list[str], out: list[RawCommand], warnings: list[str]) -> None:
    entry: list[str] = []
    first, ts, entry_ts = 0, None, None

    def flush() -> None:
        if entry:
            command = joined_lines(entry, first)
            command.ts, command.actor = entry_ts, "operator"
            out.append(command)
            entry.clear()

    for number, line in enumerate(lines, start=1):
        if line.startswith("+"):
            if not entry:
                first, entry_ts = number, ts
            entry.append(line[1:])
            continue
        flush()
        stamp = _HISTORY_TIME.fullmatch(line.rstrip())
        if stamp:
            ts = iso_to_utc(stamp.group(1))
        elif line.strip():
            out.append(kept_whole(number, line, warnings, "not a prompt history line"))
    flush()


def _read_memory(lines: list[str], out: list[RawCommand]) -> None:
    entry: list[str] = []
    first = 0
    for number, line in enumerate([*lines, _SECTION], start=1):
        if line.strip() == _SECTION:
            while entry and not entry[-1].strip():
                entry.pop()
            if entry:
                command = joined_lines(entry, first)
                command.actor = "agent_reasoning"
                out.append(command)
            entry = []
        elif entry or line.strip():
            if not entry:
                first = number
            entry.append(line)


def _form_by_content(text: str, lines: list[str]) -> str:
    """Which Hermes file text is, when its name does not say: a JSON document, JSON lines, the prompt history, a log,
    or else a memory file."""
    if text.lstrip().startswith("{"):
        return "document"
    first = next((line for line in lines if line.strip()), "")
    if first.startswith("+") or _HISTORY_TIME.fullmatch(first.rstrip()):
        return "history"
    if _LOG_START.match(first):
        return "log"
    if any(line.lstrip().startswith("{") for line in lines if line.strip()):
        return "jsonl"  # JSON lines after a first line that is not one
    return "memory"


def read_hermes(text: str, name: str = "") -> tuple[list[RawCommand], list[str]]:
    """Read a Hermes session snapshot, request dump, gateway transcript, log, prompt history or memory file. The file's
    name decides which, when it says (.hermes_history, .jsonl, .json, .log, .md); otherwise its content does."""
    out: list[RawCommand] = []
    warnings: list[str] = []
    lines = split_lines(text)
    low = name.lower()
    by_name = _FORM_BY_NAME.search(low)
    form = "history" if "hermes_history" in low else _FORMS[by_name.group(1)] if by_name else None
    form = form or _form_by_content(text, lines)
    if form == "document":
        try:
            document = json.loads(text)
        except (ValueError, RecursionError):
            document = None
        if is_operator_config(document):
            return [], [f"line 1: {CONFIG_NOTE}"]
        if isinstance(document, dict) and ("messages" in document or "request" in document):
            _read_document(text, document, out, warnings)
            return out, warnings
        if document is not None and not (isinstance(document, dict) and "role" in document):  # one line is a message
            return [], ["line 1: a JSON document that is not a Hermes session or request dump; not read"]
        form = "jsonl"
    if form == "jsonl":
        _read_jsonl(text, out, warnings)
    elif form == "history":
        _read_history(lines, out, warnings)
    elif form == "log":
        _read_log(lines, out)
    else:
        _read_memory(lines, out)
    return out, warnings


def _sqlite_steps():
    """A progress handler that stops a query once it has run _MAX_STEP_CHUNKS chunks of virtual machine steps."""
    count = [0]

    def handler() -> int:
        count[0] += 1
        return 1 if count[0] > _MAX_STEP_CHUNKS else 0

    return handler


def read_hermes_state(data: bytes, required: bool = True) -> tuple[list[RawCommand], list[str]] | None:
    """Read the messages table of a Hermes state database held in data, never touching a file: the bytes are loaded
    into an in-memory database (Python 3.11 or later), with SQLite's defensive settings, an untrusted schema and a
    step budget. Rows come in insertion order (id), each as the chat message it stores; line is the row's place.

    A database whose messages table is missing or lacks session_id, role and content is not Hermes's: with required,
    that is a warning and no lines; without it (auto detection), None, so parse records the file as binary. A WAL
    database is read without its -wal file, so changes not yet checkpointed are missing."""
    try:
        import sqlite3
    except ImportError:
        note = "line 1: this Python has no sqlite3 module; the state database was not read"
        return ([], [note]) if required else None
    if not hasattr(sqlite3.Connection, "deserialize"):
        return ([], ["line 1: reading a state database needs Python 3.11 or later; not read"]) if required else None
    if data[18:20] == bytes((2, 2)):  # WAL mode, which an in-memory database cannot open: read it as rollback mode
        data = data[:18] + bytes((1, 1)) + data[20:]
    out: list[RawCommand] = []
    warnings: list[str] = []
    connection = sqlite3.connect(":memory:")
    number = 0
    try:
        if hasattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE"):
            connection.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        if hasattr(sqlite3, "SQLITE_DBCONFIG_TRUSTED_SCHEMA"):
            connection.setconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA, False)
        connection.text_factory = lambda value: value.decode("utf-8", "replace")
        connection.set_progress_handler(_sqlite_steps(), _STEP_CHUNK)
        connection.deserialize(data)
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA query_only = ON")
        kinds = connection.execute("SELECT type FROM sqlite_master WHERE name = 'messages'").fetchall()
        columns = [row[1] for row in connection.execute("PRAGMA table_info(messages)")] if kinds == [("table",)] else []
        if not {"session_id", "role", "content"} <= set(columns):
            if not required:
                return None
            return [], ["line 1: an SQLite database without Hermes's messages table; not read"]
        wanted = [name for name in _STATE_COLUMNS if name in columns]
        order = ' ORDER BY "id"' if "id" in wanted else ""
        query = "SELECT " + ", ".join(f'"{name}"' for name in wanted) + " FROM messages" + order
        for number, row in enumerate(connection.execute(query), start=1):
            message = {name: value.decode("utf-8", "replace") if isinstance(value, bytes) else value
                       for name, value in zip(wanted, row) if value is not None}
            message.pop("id", None)
            read_safely(lambda m, n, _, o, w: read_message(m, n, o, w, _message_ts(m, n, w)), message, number,
                        as_text({k: v for k, v in message.items() if isinstance(v, (str, int, float))}), out,
                        warnings)
    except sqlite3.Error as exc:
        if not required and not out and number == 0:
            return None
        where = f"after row {number}" if number else "at the start"
        warnings.append(f"line {max(number, 1)}: state database not read {where} ({type(exc).__name__})")
    finally:
        connection.close()
    return out, warnings
