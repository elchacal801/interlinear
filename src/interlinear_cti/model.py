"""The transcript.json data model, with loading and atomic saving."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import fileio

SCHEMA_MAJOR = "0"

Actor = Literal["operator", "agent_tool", "agent_reasoning", "tool_output", "unknown"]
GlossSource = Literal["rule", "model", "analyst", "none", "pending"]
Status = Literal["active", "revoked", "deprecated", "unknown"]
SourceKind = Literal["bash_history", "zsh_history", "powershell_history", "script", "agent_jsonl", "pentagi", "unknown"]
IocType = Literal["url", "ipv4", "ipv6", "domain", "hash", "path", "user", "port"]
Confidence = Literal["high", "medium", "low"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Technique(_Strict):
    id: str
    framework: Literal["attack", "atlas"] = "attack"
    status: Status = "unknown"
    name: str | None = None
    replaced_by: list[str] = Field(default_factory=list)


class IOC(_Strict):
    type: IocType
    value: str


class Gloss(_Strict):
    source: GlossSource = "pending"
    rule_id: str | None = None
    meaning: str | None = None
    techniques: list[Technique] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    confidence: Confidence | None = None
    note: str | None = None
    by: str | None = None
    at: str | None = None


class Source(_Strict):
    id: int
    name: str
    sha256: str
    size: int
    kind: SourceKind
    agent_framework: str | None = None
    parsed_at: str
    rejected: str | None = None
    # Why no line of this file or session is labeled context: it holds a NUL, a CR or another control character,
    # which bash may read differently than the stored lines show (set by parse; see rules.plainly_literal).
    no_context: str | None = None


class Part(_Strict):
    """Where a line sits in the agent tool call it was split from, when the call held more than one command. The
    call is the record at the line's source and line. index counts from 1 up to of; offset is where the part starts
    in the call's command as the agent sent it, in characters; the first part (index 1) also holds the whole command,
    stored as line text is (controls shown, defanged and bounded), so the call can be shown as it was sent."""
    index: int = Field(ge=1)
    of: int = Field(ge=2)
    offset: int = Field(ge=0)
    command: str | None = None


class Line(_Strict):
    n: int
    source: int
    line: int
    ts: str | None = None
    actor: Actor = "unknown"
    text: str
    gloss: Gloss = Field(default_factory=Gloss)
    history: list[Gloss] = Field(default_factory=list)
    part: Part | None = None


class Transcript(_Strict):
    interlinear_version: str
    rules_version: str | None = None
    case: str | None = None
    datasets: dict[str, str] = Field(default_factory=dict)
    sources: list[Source] = Field(default_factory=list)
    lines: list[Line] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class TranscriptError(ValueError):
    """The file is not a valid transcript.json for this version of Interlinear."""


def load(path: str | Path) -> Transcript:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))  # accepts the BOM Windows PowerShell 5.1 writes
    except (OSError, ValueError, RecursionError) as exc:
        raise TranscriptError(f"{p}: not a readable transcript.json ({exc})") from exc
    if not isinstance(data, dict) or "interlinear_version" not in data:
        raise TranscriptError(f"{p}: not an Interlinear transcript")
    major = str(data["interlinear_version"]).split(".", 1)[0]
    if major != SCHEMA_MAJOR:
        raise TranscriptError(
            f"{p}: transcript version {data['interlinear_version']} is not supported (expected {SCHEMA_MAJOR}.x)"
        )
    try:
        return Transcript.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(x) for x in first["loc"])
        raise TranscriptError(
            f"{p}: invalid transcript ({exc.error_count()} errors; first at {where}: {first['msg']})"
        ) from exc


def save(transcript: Transcript, path: str | Path) -> None:
    """Write the transcript atomically through fileio, creating missing folders. An OSError is raised as it came."""
    fileio.atomic_write(path, transcript.model_dump_json(indent=2))
