"""The Markdown interlinear view: each line, then its techniques and source, then its meaning.

transcript.md is read on GitHub, in editors and in terminals, and may be published. Line text, source names,
warnings and gloss text came from an attacker or a model, so none of it may become live Markdown, HTML, a link or a
display trick:
- every line block goes inside a fenced code block longer than any backtick run inside it;
- every other value from the transcript (the case, source names, rejection reasons, sha256 prefixes, rule and
  dataset versions, and warnings) is an inline code span, which shows its text literally: no link, autolink,
  emphasis, entity, HTML or fence;
- a last pass over the whole view shows every invisible character as U+27E8, U+XXXX, U+27E9, the form the parse
  stage and glossing use. It keeps newlines and tabs, which are inert in the fence; values outside it are code
  spans, which show their own line breaks and tabs as control pictures.
"""

from __future__ import annotations

import functools
import hashlib
import re
import unicodedata
from collections import Counter

from .model import Gloss, Line, Technique, Transcript
from .textshow import code_point, is_hidden

INDENT = " " * 6
ACTOR_TAGS = {"operator": "[operator]", "agent_tool": "[agent tool]",
              "agent_reasoning": "[agent reasoning]", "unknown": "[unknown]"}
CALL_MARK = "| "  # before each line of a split agent tool call's whole command, shown above its first part
ELLIPSIS = chr(0x2026)
SEPARATOR = f" {chr(0x00B7)} "  # a middle dot between techniques, and between the parts of the Glosses line
TITLE_SUFFIX = ": interlinear transcript"
# The first line of every view this module writes, before and after its values became code spans. The CLI replaces
# an existing file only when its first line is one, so render cannot be aimed at a file it did not write.
_HEADER = re.compile("# .+" + re.escape(TITLE_SUFFIX))
_BACKTICKS = re.compile("`+")
# The characters the last pass looks at: everything but printable ASCII, the tab and the newline.
_CANDIDATES = re.compile("[^" + chr(0x09) + chr(0x0A) + chr(0x20) + "-" + chr(0x7E) + "]")
# A line break inside a code span would end its line, and the next line could open a block (a ~~~ fence, a
# heading), so CR and LF in a value become control pictures, as the parse stage writes them in line text. A tab
# becomes one too, so the only tabs in the view are the ones inside the fence.
_SPAN_PICTURES = {0x09: chr(0x2409), 0x0D: chr(0x240D), 0x0A: chr(0x240A)}


@functools.lru_cache(maxsize=4096)
def _visible(ch: str) -> str:
    if unicodedata.category(ch) == "Cc" or is_hidden(ch):
        return code_point(ch)
    return ch


def show_invisible(text: str) -> str:
    """Show each invisible character as U+27E8, U+XXXX, U+27E9 (five hex digits past U+FFFF).

    That is every control character but the newline and the tab (C0, DEL and C1, so also CR and the escape that
    starts a terminal sequence), and every hidden character (textshow.is_hidden: format characters such as bidi
    controls, zero-width characters, the BOM, the soft hyphen and the tag characters; U+2028 and U+2029; the
    default-ignorable characters outside Cf, such as variation selectors and Hangul fillers; and U+2800). The forms
    are visible text, so a second pass changes nothing.
    """
    return _CANDIDATES.sub(lambda m: _visible(m.group()), text)


def _longest_backtick_run(texts: list[str]) -> int:
    return max((len(run) for text in texts for run in _BACKTICKS.findall(text)), default=0)


def code_span(value: str) -> str:
    """value as an inline code span, which every CommonMark renderer shows as literal text on one line.

    CR, LF and tab become control pictures and invisible characters are shown. The backtick run around the value is
    one longer than any run inside it. A space pads a value that starts or ends with a backtick, or that starts and
    ends with a space without being all spaces, since CommonMark strips one space from each end of such a span.
    """
    value = show_invisible(value.translate(_SPAN_PICTURES))
    if not value:
        return "` `"
    ticks = "`" * (_longest_backtick_run([value]) + 1)
    stripped = value[0] == " " and value[-1] == " " and value.strip(" ") != ""
    pad = " " if value[0] == "`" or value[-1] == "`" or stripped else ""
    return f"{ticks}{pad}{value}{pad}{ticks}"


def _technique_label(t: Technique) -> str:
    if t.status == "revoked":
        return f"{t.id} (revoked, now {', '.join(t.replaced_by) or 'unknown'})"
    name = f" {t.name}" if t.name else ""
    deprecated = " (deprecated)" if t.status == "deprecated" else ""
    return f"{t.id}{name}{deprecated}"


def is_render_header(line: str) -> bool:
    """Whether line (without its line ending) is the first line of a view render_markdown writes."""
    return _HEADER.fullmatch(line) is not None


def _source_tag(g: Gloss) -> str:
    if g.source == "rule":
        return f"[rule: {g.rule_id}]"
    if g.source in ("model", "analyst"):
        # A model's or analyst's confidence is part of the tag, so a low guess never reads like a high one. With no
        # techniques, the gloss marks a context line; the tag still says who marked it.
        who = f"{g.source}: {g.by}" + (f"{SEPARATOR}{g.confidence}" if g.confidence else "")
        return f"[{who}]" if g.techniques else f"[context; {who}]"
    if g.source == "none":
        return "[context]"  # only the rule library's context lines (and tool output, shown collapsed) use none
    return "[pending]"


def _rule_versions(transcript: Transcript) -> list[str]:
    """Every rule library version in the transcript: the rule glosses' own by values, and rules_version.

    A later gloss run with a newer library leaves the older rule glosses in place, and an analyst's gloss moves the
    rule gloss it replaces to the line's history, so every version whose glosses the transcript holds is named.
    """
    versions = {g.by.removeprefix("rules ") for line in transcript.lines for g in (line.gloss, *line.history)
                if g.rule_id and g.by and g.by.startswith("rules ")}
    if transcript.rules_version:
        versions.add(transcript.rules_version)
    return sorted(versions, key=lambda v: [part.zfill(8) for part in v.split(".")])


def _block(line: Line, agent: bool) -> list[str]:
    if line.actor == "tool_output":
        digest = hashlib.sha256(line.text.encode("utf-8")).hexdigest()[:12]
        return [f"{line.n:>4}  [output: {line.text.count(chr(10)) + 1} lines, sha256 {digest}{ELLIPSIS}]"]
    first, *rest = line.text.split("\n")
    prefix = f"{ACTOR_TAGS.get(line.actor, '[unknown]')} " if agent else ""
    block = []
    if line.part is not None:
        # A part of a split agent tool call says which part it is, and the first part shows the call as it was sent.
        prefix = f"{ACTOR_TAGS.get(line.actor, '[unknown]')[:-1]} {line.part.index}/{line.part.of}] "
        if line.part.command is not None:
            block.append(INDENT + f"[agent tool call, record line {line.line}, {line.part.of} commands]")
            block += [INDENT + CALL_MARK + text for text in line.part.command.split("\n")]
    block += [f"{line.n:>4}  {prefix}{first}", *(INDENT + r for r in rest)]
    g = line.gloss
    techniques = SEPARATOR.join(_technique_label(t) for t in g.techniques)
    tag = _source_tag(g)
    block.append(INDENT + (f"{techniques}   {tag}" if techniques else tag))
    if g.meaning and g.source != "pending":
        block.append(INDENT + g.meaning)
    if g.note:
        block.append(INDENT + f"note: {g.note}")
    return block


def render_markdown(transcript: Transcript) -> str:
    title = code_span(transcript.case) if transcript.case else "Transcript"
    out = [f"# {title}{TITLE_SUFFIX}", ""]
    described = []
    for s in transcript.sources:
        count = sum(1 for line in transcript.lines if line.source == s.id)
        state = f"rejected: {code_span(s.rejected)}" if s.rejected else f"{count} lines"
        described.append(f"{code_span(s.name)} (sha256 {code_span(s.sha256[:12])}{ELLIPSIS}, {state})")
    # A blank line after Sources, so GitHub shows the Glosses line as a line of its own.
    out += ["Sources: " + "; ".join(described), ""]
    counts = Counter(line.gloss.source for line in transcript.lines if line.actor != "tool_output")
    summary = ", ".join(f"{counts.get(k, 0)} {k}" for k in ("rule", "model", "analyst", "none", "pending"))
    extra = []
    versions = _rule_versions(transcript)
    if versions:
        extra.append("rules " + ", ".join(code_span(v) for v in versions))
    if transcript.datasets.get("attack-enterprise"):
        extra.append(f"ATT&CK {code_span(transcript.datasets['attack-enterprise'])}")
    out.append("Glosses: " + SEPARATOR.join([summary, *extra]))
    agent = any(s.kind in ("agent_jsonl", "pentagi") for s in transcript.sources)
    sections = []
    for s in transcript.sources:
        lines = [line for line in transcript.lines if line.source == s.id]
        if lines:
            sections.append((s, "\n\n".join("\n".join(_block(line, agent)) for line in lines)))
    fence = "`" * max(3, _longest_backtick_run([body for _, body in sections]) + 1)
    for s, body in sections:
        out += ["", f"## {code_span(s.name)}", "", f"{fence}text", body, fence]
    if transcript.warnings:
        out += ["", "## Warnings", ""] + [f"- {code_span(w)}" for w in transcript.warnings]
    # The last pass, over everything: the fence bodies, and the code spans as defense in depth. It writes no
    # backtick and no newline, so the fence and the spans stay as built.
    return show_invisible("\n".join(out) + "\n")
