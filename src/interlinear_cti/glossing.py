"""Applying glosses to a transcript: rules first, then model or analyst glosses submitted as JSON.

A glosses file comes from a model that has read attacker text, so it may be prompt-injected, and every field in it is
untrusted:
- entries are validated with strict types and size limits, and an entry that fails is rejected whole;
- free text (meaning, note, artifacts, IOC values and the by label) goes through the parse stage's pipeline before it
  is stored: control pictures, invisible format characters shown, no line breaks, then defanged, with blobs hashed
  and long text truncated;
- every name in a domain or URL IOC's host is defanged, and such a value may not hold whitespace;
- a rejection reason never echoes raw input: it is defanged, escaped and capped.
Rule glosses come from the trusted library and are stored as they are, except that a rule match on a file parse could
not classify is marked less certain.
"""

from __future__ import annotations

import re
from collections import Counter
from itertools import islice
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

from .model import IOC, Gloss, IocType, Technique, Transcript
from .normalize import defang, normalize_text
from .parse import escape_controls
from .redact import redact
from .rules import Library, changes_later_commands, gloss_for, partial_reason
from .textshow import show_controls, show_hidden

# Rules gloss commands only. Agent reasoning, chat typed into an agent (an agent log's operator lines) and an agent
# log's lines of unknown actor are prose, where a rule matching a word would claim a technique nobody ran; they stay
# pending, for the model. Tool output is never glossed.
_COMMAND_SOURCES = frozenset({"bash_history", "zsh_history", "powershell_history", "script"})
# A rule match on a file parse could not classify is less certain: the text may not be commands at all.
UNKNOWN_FORMAT_NOTE = "source format unknown; rule applied to unclassified text"

# The --by label: one short name, such as a model ID or an analyst's name, never more lines or markup. \w takes
# Unicode letters, so a name such as Munoz with a tilde fits; the first character is a letter or digit, not "_".
BY_LABEL = re.compile(r"[^\W_][\w ._:@-]{0,63}")
BY_RULE = "a letter or digit, then up to 63 letters, digits, spaces or . _ : @ -"
MAX_REASON = 300  # characters in a rejection reason or a warning
MAX_ECHOED_ID = 32  # an unknown technique ID longer than this is described, never echoed

# Hidden characters (textshow.is_hidden: format characters such as bidi controls, zero-width characters, the BOM and
# the tag characters U+E0000 to U+E007F, which can carry hidden text; the line and paragraph separators; the
# default-ignorable characters outside Cf, such as variation selectors and Hangul fillers; and U+2800) are written as
# parse writes them in line text: U+27E8, U+NNNN (five hex digits past U+FFFF), U+27E9.
_WHITESPACE = re.compile(r"\s")  # Unicode whitespace, U+00A0 and U+2028 included
# The start of a URL's authority: an optional scheme followed by a slash (so host:port is not read as a scheme), then
# up to two slashes. The authority ends at / ? # or a backslash.
_URL_PREFIX = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*:(?=/))?/{0,2}")
_AUTHORITY_END = re.compile(r"[/?#\\]")
# A dotted name in a domain IOC or a URL's authority: labels of word characters (Unicode letters included, for IDNs)
# and hyphens. It starts where no name continues (a lone dot before it is allowed, as in .evil.zip) and ends where no
# name continues (a final dot is allowed, as in evil.zip.). One followed by [.] already has its last dot defanged.
# The lookarounds keep starts and ends at name boundaries, so the scan stays linear.
_NAME = re.compile(r"(?<![\w-])(?<![\w-]\.)[\w-]+(?:\.[\w-]+)+(?![\w-]|\.[\w-]|\[\.\])")


def _rules_apply(actor: str, kind: str | None) -> bool:
    if actor == "agent_tool":
        return True
    if actor == "operator":
        return kind in _COMMAND_SOURCES
    if actor == "unknown":
        return kind == "unknown"
    return False  # agent_reasoning and tool_output


def _context_limits(transcript: Transcript, kinds: dict[int, str]) -> dict[int, tuple[int, str, int]]:
    """For each source, where its context labels stop: the file line of its first record that can change how later
    commands resolve or run (rules.changes_later_commands), why, and the first such record's n. From there on, in
    file order or in the transcript's order (which may be by time), no line of the source is labeled context."""
    limits: dict[int, tuple[int, str, int]] = {}
    for line in transcript.lines:
        if not _rules_apply(line.actor, kinds.get(line.source)):
            continue
        reason = changes_later_commands(line.text)
        if reason is None:
            continue
        first, why, n = limits.get(line.source, (line.line, reason, line.n))
        if line.line < first:
            first, why = line.line, reason
        limits[line.source] = (first, why, min(n, line.n))
    return limits


def apply_rules(transcript: Transcript, library: Library, at: str) -> dict[str, int]:
    """Gloss the pending command lines with the rules. A context rule may claim a line only when its source holds no
    control character (Source.no_context) and no record before it that can change how later commands run; a source
    whose context labels stop at such a record gets a warning that names its line."""
    counts: Counter[str] = Counter()
    kinds = {source.id: source.kind for source in transcript.sources}
    names = {source.id: source.name for source in transcript.sources}
    denied = {source.id for source in transcript.sources if source.no_context}
    limits = _context_limits(transcript, kinds)
    for sid, (first, why, _) in sorted(limits.items()):
        warning = (f"{names.get(sid, sid)}: line {first}: {why} can change how later commands run; no line from there "
                   "on is labeled context")
        if sid not in denied and warning not in transcript.warnings:
            transcript.warnings.append(warning)
    for line in transcript.lines:
        if line.gloss.source != "pending" or not _rules_apply(line.actor, kinds.get(line.source)):
            continue
        first, _, n = limits.get(line.source, (line.line + 1, "", line.n + 1))
        # A line decoded from a payload is never context: it was hidden on purpose.
        context = line.source not in denied and line.line < first and line.n < n and line.decoded is None
        # A record that spans lines goes to the model unless a rule reads it whole (Library.match_record).
        rule = library.match_record(line.text, context=context, zsh=kinds.get(line.source) == "zsh_history")
        if rule is None:
            counts["unmatched"] += 1
            continue
        gloss = gloss_for(library, rule, line.text, at)
        if kinds.get(line.source) == "unknown":  # at most medium confidence, and say why
            if gloss.confidence == "high":
                gloss.confidence = "medium"
            gloss.note = UNKNOWN_FORMAT_NOTE
        gloss.partial = partial_reason(rule, line.text)  # then the line goes to the model too
        line.gloss = gloss
        counts[line.gloss.source] += 1
        if gloss.partial:
            counts["partial"] += 1
    transcript.rules_version = library.version
    return dict(counts)


def is_open(gloss: Gloss) -> bool:
    """Whether a line still waits for the model: it is pending, or a rule glossed only part of it (Gloss.partial)."""
    return gloss.source == "pending" or (gloss.source == "rule" and bool(gloss.partial))


def _pending_row(line, redact_secrets: bool) -> dict:
    row = {"n": line.n, "actor": line.actor, "text": redact(line.text) if redact_secrets else line.text}
    if line.decoded is not None:
        row["decoded_from"] = line.decoded.parent
    if line.gloss.source == "rule":  # partial: what the rule found, and what it left
        row["rule"] = {"id": line.gloss.rule_id, "techniques": [t.id for t in line.gloss.techniques],
                       "partial": line.gloss.partial}
    return row


def pending_lines(transcript: Transcript, limit: int = 50, after: int = 0, redact_secrets: bool = False) -> list[dict]:
    """Up to limit lines numbered above after that wait for the model (is_open), so a caller can page through them
    with the last n it saw. A line a rule glossed only in part carries what the rule found. With redact_secrets, each
    credential in the text is redacted (redact.redact); the transcript keeps it."""
    if limit < 1:
        raise ValueError("limit must be at least 1")
    rows = (_pending_row(line, redact_secrets) for line in transcript.lines
            if line.n > after and is_open(line.gloss) and line.actor != "tool_output")
    return list(islice(rows, limit))


def show_format(text: str) -> str:
    """Write each hidden character (textshow.is_hidden: format characters, U+2028 and U+2029, the default-ignorable
    characters outside Cf, and U+2800) as U+27E8, U+NNNN, U+27E9."""
    return show_hidden(text)


def clean_text(text: str) -> str:
    """The parse stage's pipeline for line text, for untrusted free text: one visible, defanged, bounded line.

    Control characters become control pictures (CR included), hidden characters (textshow.is_hidden) are shown the
    same way as C1 controls, newlines become spaces, then normalize_text defangs, hashes blobs and truncates.
    """
    return normalize_text(show_format(show_controls(text)).replace(chr(0x0A), " "))


def _defang_names(text: str) -> str:
    return _NAME.sub(lambda m: "[.]".join(m.group().rsplit(".", 1)), text)


def _defang_host(value: str, url: bool) -> str:
    """Defang every name that defang() left live in a domain IOC, or in a URL IOC's authority, whatever its TLD.

    defang() leaves names whose TLD doubles as a file extension (.zip, .mov, .app) or is an IDN (xn--) live, so a
    script name in line text stays readable. A typed domain or URL IOC names a host, so each dotted name in it has its
    last dot defanged, unless that is already [.]. That covers a name before or after one already defanged (as in
    x[.]y.evil.zip or a.evil.zip,b.evil.zip) and a URL's userinfo. A URL's path keeps its file names.
    """
    if not url:
        return _defang_names(value)
    start = _URL_PREFIX.match(value).end()
    stop = _AUTHORITY_END.search(value, start)
    end = stop.start() if stop else len(value)
    return value[:start] + _defang_names(value[start:end]) + value[end:]


def _clean_ioc(ioc_type: str, value: str) -> str:
    text = clean_text(value)
    return _defang_host(text, url=ioc_type == "url") if ioc_type in ("domain", "url") else text


def _reason(text: str) -> str:
    """A rejection reason or warning: defanged, with controls escaped, at most MAX_REASON characters.

    The cut text is defanged again, since a cut can leave a live name, such as a.evil.com from a.evil.com.x[.]net.
    The raw text is cut first too, at four times the cap, so a huge key in an entry costs nothing to describe.
    """
    text = escape_controls(normalize_text(show_format(text[: MAX_REASON * 4])), keep="")
    if len(text) > MAX_REASON:
        text = defang(text[: MAX_REASON - 3])[: MAX_REASON - 3] + "..."
    return text


def _label(n: object) -> str:
    """n for a reason: only an int is echoed (bool is not one), and only one of sane size."""
    return str(n) if type(n) is int and abs(n) < 10**18 else "?"


def _shown_id(technique_id: str) -> str:
    if not technique_id:
        return "(empty)"
    if len(technique_id) > MAX_ECHOED_ID:
        return f"(an ID of {len(technique_id)} characters)"
    return technique_id


def _revoked(t: Technique) -> str:
    return f"{t.id} is revoked" + (f"; use {' or '.join(t.replaced_by)}" if t.replaced_by else "")


class IocInput(BaseModel):
    """An IOC in a glosses file. Its value is cleaned before it is stored as a model.IOC."""

    model_config = ConfigDict(extra="forbid")
    type: IocType
    value: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def _one_host(self) -> IocInput:
        # Whitespace would let one value hold several names, such as "a.evil.zip b.evil.zip".
        if self.type in ("domain", "url") and _WHITESPACE.search(self.value):
            raise ValueError("a domain or url IOC cannot contain whitespace")
        return self


class GlossInput(BaseModel):
    """One entry of a glosses file, as written by the gloss skill or an analyst. Every field is untrusted."""

    model_config = ConfigDict(extra="forbid")
    n: int = Field(strict=True)
    meaning: Annotated[str, StringConstraints(strip_whitespace=True), Field(min_length=1, max_length=1000)]
    techniques: list[str] = Field(default_factory=list, max_length=10)
    artifacts: list[Annotated[str, Field(min_length=1, max_length=120)]] = Field(default_factory=list, max_length=20)
    iocs: list[IocInput] = Field(default_factory=list, max_length=50)
    confidence: Literal["high", "medium", "low"]
    note: str | None = Field(default=None, max_length=2000)
    context: bool = Field(default=False, strict=True)


def apply_glosses(transcript: Transcript, entries: list, *, source: str, by: str, resolver, at: str,
                  warnings: list[str] | None = None) -> tuple[int, list[str]]:
    """Validate glosses and merge them into the transcript. Returns (applied, rejection reasons).

    source is "model" (fills pending lines only) or "analyst" (may replace an earlier gloss, which moves to history).
    by must match BY_LABEL. A warning, such as a deprecated technique on an applied gloss, is appended to warnings.
    """
    if source not in ("model", "analyst"):
        raise ValueError(f"source must be model or analyst, not {source!r}")
    if not isinstance(by, str) or not BY_LABEL.fullmatch(by):
        raise ValueError(f"by must be a short label: {BY_RULE}")
    by = clean_text(by)
    if warnings is None:
        warnings = []
    lines = {line.n: line for line in transcript.lines}
    seen: set[int] = set()
    applied = 0
    rejected: list[str] = []
    for raw in entries:
        n = raw.get("n") if isinstance(raw, dict) else None
        label = _label(n)
        if type(n) is int:  # a repeat is rejected even when the first entry for that line was invalid
            if n in seen:
                rejected.append(_reason(f"line {label}: a repeated line number; only the first entry for a line "
                                        "is used"))
                continue
            seen.add(n)
        try:
            entry = GlossInput.model_validate(raw)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(x) for x in first["loc"])
            rejected.append(_reason(f"line {label}: invalid entry ({where + ': ' if where else ''}{first['msg']})"))
            continue
        line = lines.get(entry.n)
        problem: str | None = None
        checked: list[Technique] = []
        if line is None:
            problem = "no such line"
        elif line.actor == "tool_output":
            problem = "tool output is not glossed"
        elif entry.context and line.decoded is not None:
            problem = "a line decoded from an encoded payload is never context"
        elif source == "model" and not is_open(line.gloss):
            problem = f"already glossed ({line.gloss.source}); model glosses only fill pending lines"
        elif entry.context and entry.techniques:
            problem = "a context gloss carries no techniques"
        elif not entry.context and not entry.techniques:
            problem = "give at least one technique, or set context to true"
        else:
            checked = [resolver.check(tid) for tid in entry.techniques]
            unknown = [t.id for t in checked if t.status == "unknown"]
            if unknown:
                problem = f"unknown technique(s) {', '.join(_shown_id(tid) for tid in unknown)}"
        # One of each technique, in first-seen order; the resolver has already canonicalized the IDs.
        techniques = list({(t.framework, t.id): t for t in checked}.values())
        revoked = [t for t in techniques if t.status == "revoked"]
        if problem is None and revoked and source == "model":
            problem = "; ".join(_revoked(t) for t in revoked)  # names the replacement, so the skill can resubmit
        if problem is not None:
            rejected.append(_reason(f"line {label}: {problem}"))
            continue
        notes = [f"{_revoked(t)} (accepted for an analyst gloss)" for t in revoked]
        notes += [f"{t.id} is deprecated (accepted)" for t in techniques if t.status == "deprecated"]
        # Model and analyst context glosses keep their source, so readers can tell them from the rules' context lines.
        new = Gloss(source=source, meaning=clean_text(entry.meaning), techniques=techniques,
                    artifacts=[clean_text(a) for a in entry.artifacts],
                    iocs=[IOC(type=i.type, value=_clean_ioc(i.type, i.value)) for i in entry.iocs],
                    confidence=entry.confidence, note=None if entry.note is None else clean_text(entry.note),
                    by=by, at=at)
        if line.gloss.source != "pending":
            line.history.append(line.gloss)
        line.gloss = new
        warnings.extend(_reason(f"line {label}: {note}") for note in notes)
        applied += 1
    return applied, rejected
