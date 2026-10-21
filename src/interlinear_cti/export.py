"""Export glossed lines as a Countermap scenario spec (spec section 8).

scenario.json is read in editors and on GitHub, and Countermap draws it in several formats, so every text in it that
came from the transcript (the title, the source names and each step's description) has its control and hidden
characters shown by their code points and is defanged, after any cut: a cut can leave a live host, such as
login.example-bank.com from login.example-bank.com.evil-test[.]net. Only canonical ATT&CK and ATLAS technique IDs
are exported; a hand-edited transcript can hold anything in that field.
"""

from __future__ import annotations

import re

from . import __version__
from .model import Technique, Transcript
from .normalize import defang
from .textshow import code_point, show_hidden
from .verify import CANONICAL_ID

MAX_STEPS = 100  # Countermap's scenario limit
MAX_TITLE = 200  # Countermap's title limit
MAX_DESCRIPTION = 500  # a step's description
MAX_NAMED_SOURCES = 10  # source names in the scenario's description; the rest are counted
MAX_NAMES = 300  # characters of source names in the scenario's description
MAX_LISTED_LINES = 20  # line numbers named in a warning; the rest are counted
_FIT_PASSES = 4
ORDER_NOTE = "The steps follow the transcript's line order; each cites its transcript lines and gloss sources."
NO_STEPS = "no glossed lines with techniques; the scenario has no steps"
# C0 controls, DEL and C1 controls. JSON escapes only the C0 ones, so a raw C1 control such as U+009B (CSI) would
# reach a terminal that prints the file.
_CONTROLS = re.compile("[" + chr(0) + "-" + chr(0x1F) + chr(0x7F) + "-" + chr(0x9F) + "]")


def _primary(technique: Technique) -> str:
    if technique.status == "revoked" and technique.replaced_by:
        return technique.replaced_by[0]
    return technique.id


def _unreplaced(technique: Technique) -> bool:
    return technique.status == "revoked" and not technique.replaced_by


def _ranges(numbers: list[int]) -> str:
    parts: list[str] = []
    start = prev = numbers[0]
    for n in numbers[1:]:
        if n == prev + 1:
            prev = n
            continue
        parts.append(f"{start}-{prev}" if start != prev else f"{start}")
        start = prev = n
    parts.append(f"{start}-{prev}" if start != prev else f"{start}")
    return ("Line " if len(numbers) == 1 else "Lines ") + ", ".join(parts)


def _shown(text: str) -> str:
    """text with each control character and each hidden character (textshow.is_hidden) shown by its code point."""
    return show_hidden(_CONTROLS.sub(lambda m: code_point(m.group()), text))


def _fit(text: str, limit: int) -> str:
    """text with its invisible characters shown and defanged, in at most limit characters.

    A longer text is cut to leave room for "...", and the cut is defanged, which can lengthen it, then cut again
    until it fits. Should that not settle, the cut ends at its last space instead, leaving out the name it ran into.
    """
    text = defang(_shown(text))
    if len(text) <= limit:
        return text
    room = limit - 3
    cut = text[:room]
    for _ in range(_FIT_PASSES):
        fanged = defang(cut)
        if len(fanged) <= room:
            return fanged + "..."
        cut = fanged[:room]
    space = cut.rfind(" ")
    return (cut[:space] if space > 0 else "") + "..."


def _source_names(transcript: Transcript) -> str:
    """The first source names, up to MAX_NAMED_SOURCES of them in at most MAX_NAMES characters, then how many more."""
    named: list[str] = []
    used = 0
    for source in transcript.sources[:MAX_NAMED_SOURCES]:
        name = _fit(source.name, MAX_NAMES)
        cost = len(name) + (2 if named else 0)
        if named and used + cost > MAX_NAMES:
            break
        named.append(name)
        used += cost
    rest = len(transcript.sources) - len(named)
    return ", ".join(named) + (f" and {rest} more" if rest else "")


def _lines_warning(numbers: list[int], problem: str) -> str:
    listed = _ranges(numbers[:MAX_LISTED_LINES])
    more = f" and {len(numbers) - MAX_LISTED_LINES} more" if len(numbers) > MAX_LISTED_LINES else ""
    return f"{listed}{more} {'has' if len(numbers) == 1 else 'have'} {problem}"


def export_scenario(transcript: Transcript, title: str | None = None) -> tuple[dict, list[str]]:
    usable = []
    non_canonical: list[int] = []  # lines whose technique ID is not an ATT&CK or ATLAS technique ID
    for line in transcript.lines:
        if line.actor == "tool_output" or line.gloss.source not in ("rule", "model", "analyst"):
            continue
        if line.gloss.techniques:
            if CANONICAL_ID.fullmatch(_primary(line.gloss.techniques[0])):
                usable.append(line)
            else:
                non_canonical.append(line.n)
    # A model gloss with no techniques marks a context line. Those lines are left out, so the reader is told.
    model_context = sum(1 for line in transcript.lines
                        if line.actor != "tool_output" and line.gloss.source == "model" and not line.gloss.techniques)
    # A step is a run of consecutive lines with the same primary technique, actor and source file, so lines from two
    # files never merge into one step. The steps keep the transcript's order.
    groups: list[dict] = []
    for line in usable:
        key = (_primary(line.gloss.techniques[0]), line.actor, line.source)
        if groups and groups[-1]["key"] == key:
            groups[-1]["lines"].append(line)
        else:
            groups.append({"key": key, "technique": key[0], "actor": line.actor, "lines": [line]})
    warnings: list[str] = []
    if model_context:
        marked = "line was marked context by a model and is" if model_context == 1 else \
            "lines were marked context by a model and are"
        warnings.append(f"{model_context} {marked} not in the scenario")
    if non_canonical:
        warnings.append(_lines_warning(non_canonical, "a technique ID that is not an ATT&CK or ATLAS technique ID; "
                                                      "left out of the scenario"))
    if len(groups) > MAX_STEPS:
        warnings.append(f"{len(groups)} steps exceed Countermap's limit of {MAX_STEPS}; exported the first {MAX_STEPS}")
        groups = groups[:MAX_STEPS]
    steps: list[dict] = []
    unreplaced: dict[str, list[str]] = {}  # a revoked technique with no replacement, and the steps that keep it
    for i, group in enumerate(groups, start=1):
        lines = group["lines"]
        sources = sorted({line.gloss.source for line in lines})
        prefix = "Model-glossed: " if sources == ["model"] else ""
        head = f"{prefix}{_ranges([line.n for line in lines])} ({', '.join(sources)}; {group['actor']})"
        meaning = lines[0].gloss.meaning
        step: dict = {"id": f"s{i}", "technique": group["technique"]}
        if i > 1:
            step["after"] = [f"s{i - 1}"]
        step["description"] = _fit(f"{head}: {meaning}" if meaning else head, MAX_DESCRIPTION)
        steps.append(step)
        if any(_unreplaced(line.gloss.techniques[0]) for line in lines):
            unreplaced.setdefault(group["technique"], []).append(step["id"])
    for technique, ids in unreplaced.items():
        warnings.append(f"{technique} is revoked and has no replacement; kept as is in "
                        f"{'step' if len(ids) == 1 else 'steps'} {', '.join(ids)}")
    if not steps:
        warnings.append(NO_STEPS)
    spec = {
        "title": _fit(title or transcript.case or "Interlinear transcript", MAX_TITLE),
        "description": f"Exported by Interlinear {__version__} from {_source_names(transcript)}. {ORDER_NOTE}",
        "authors": [],
        "steps": steps,
        "countermeasures": "auto",
        "max_countermeasures_per_step": 2,
    }
    return spec, warnings
