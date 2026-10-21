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
from .injection import aimed_at_reader
from .model import Source, Technique, Transcript
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
ORDER_NOTE = ("Steps are chained only within each source file, in its line order; the files are parallel lanes, since "
              "nothing in them orders one against another. Each step cites its transcript lines and gloss sources.")
AIMED_NOTE = ("text aimed at an analyst or AI model rather than the target (possible prompt injection); left out of the "
              "scenario")
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


def _source_names(sources: list[Source]) -> str:
    """The first source names, up to MAX_NAMED_SOURCES of them in at most MAX_NAMES characters, then how many more."""
    named: list[str] = []
    used = 0
    for source in sources[:MAX_NAMED_SOURCES]:
        name = _fit(source.name, MAX_NAMES)
        cost = len(name) + (2 if named else 0)
        if named and used + cost > MAX_NAMES:
            break
        named.append(name)
        used += cost
    rest = len(sources) - len(named)
    return ", ".join(named) + (f" and {rest} more" if rest else "")


def find_source(transcript: Transcript, wanted: str) -> int:
    """The id of the source named wanted, or whose id it is. A ValueError names the sources there are."""
    for source in transcript.sources:
        if source.name == wanted:
            return source.id
    if wanted.isdigit() and any(source.id == int(wanted) for source in transcript.sources):
        return int(wanted)
    names = _source_names(transcript.sources)
    raise ValueError(f"no source named {wanted!r} and no source with that id; the sources are {names}")


def _lines_warning(numbers: list[int], problem: str) -> str:
    listed = _ranges(numbers[:MAX_LISTED_LINES])
    more = f" and {len(numbers) - MAX_LISTED_LINES} more" if len(numbers) > MAX_LISTED_LINES else ""
    return f"{listed}{more} {'has' if len(numbers) == 1 else 'have'} {problem}"


def export_scenario(transcript: Transcript, title: str | None = None,
                    source: int | None = None) -> tuple[dict, list[str]]:
    """A Countermap scenario spec from the glossed lines, and warnings for the reader. With source, only that
    source's lines are exported.

    Each source file is a lane: its steps are chained in its line order, and no step of one file comes after a step
    of another, since nothing in the files orders them against each other (histories without timestamps have no
    order at all). A step is a run of back-to-back lines of one source with the same primary technique, whatever the
    actor. A line whose text addresses an analyst or an AI model rather than the target (injection.aimed_at_reader)
    is left out.
    """
    chosen = [line for line in transcript.lines if source is None or line.source == source]
    usable = []
    non_canonical: list[int] = []  # lines whose technique ID is not an ATT&CK or ATLAS technique ID
    aimed: list[int] = []  # lines aimed at the reader, left out
    for line in chosen:
        if line.actor == "tool_output" or line.gloss.source not in ("rule", "model", "analyst"):
            continue
        if line.gloss.techniques:
            if aimed_at_reader(line.text):
                aimed.append(line.n)
            elif CANONICAL_ID.fullmatch(_primary(line.gloss.techniques[0])):
                usable.append(line)
            else:
                non_canonical.append(line.n)
    # A model gloss with no techniques marks a context line. Those lines are left out, so the reader is told.
    model_context = sum(1 for line in chosen
                        if line.actor != "tool_output" and line.gloss.source == "model" and not line.gloss.techniques)
    lanes: dict[int, list[dict]] = {}  # by source id, in the order the sources are listed
    for line in usable:
        groups = lanes.setdefault(line.source, [])
        technique = _primary(line.gloss.techniques[0])
        if groups and groups[-1]["technique"] == technique:
            groups[-1]["lines"].append(line)
        else:
            groups.append({"technique": technique, "lines": [line]})
    order = [s.id for s in transcript.sources if s.id in lanes] + sorted(set(lanes) - {s.id for s in transcript.sources})
    groups = [group for sid in order for group in lanes[sid]]
    names = {s.id: s.name for s in transcript.sources}
    several = len(lanes) > 1
    warnings: list[str] = []
    if model_context:
        marked = "line was marked context by a model and is" if model_context == 1 else \
            "lines were marked context by a model and are"
        warnings.append(f"{model_context} {marked} not in the scenario")
    if non_canonical:
        warnings.append(_lines_warning(non_canonical, "a technique ID that is not an ATT&CK or ATLAS technique ID; "
                                                      "left out of the scenario"))
    if aimed:
        warnings.append(_lines_warning(aimed, AIMED_NOTE))
    if len(groups) > MAX_STEPS:
        warnings.append(f"{len(groups)} steps exceed Countermap's limit of {MAX_STEPS}; exported the first {MAX_STEPS}")
        groups = groups[:MAX_STEPS]
    steps: list[dict] = []
    unreplaced: dict[str, list[str]] = {}  # a revoked technique with no replacement, and the steps that keep it
    previous: dict[int, str] = {}  # each lane's last step
    for i, group in enumerate(groups, start=1):
        lines = group["lines"]
        sid = lines[0].source
        sources = sorted({line.gloss.source for line in lines})
        actors = ", ".join(sorted({line.actor for line in lines}))
        prefix = "Model-glossed: " if sources == ["model"] else ""
        where = f"{names.get(sid, sid)}: " if several else ""
        head = f"{where}{prefix}{_ranges(sorted(line.n for line in lines))} ({', '.join(sources)}; {actors})"
        meaning = lines[0].gloss.meaning
        step: dict = {"id": f"s{i}", "technique": group["technique"]}
        if sid in previous:
            step["after"] = [previous[sid]]
        previous[sid] = step["id"]
        step["description"] = _fit(f"{head}: {meaning}" if meaning else head, MAX_DESCRIPTION)
        steps.append(step)
        if any(_unreplaced(line.gloss.techniques[0]) for line in lines):
            unreplaced.setdefault(group["technique"], []).append(step["id"])
    for technique, ids in unreplaced.items():
        warnings.append(f"{technique} is revoked and has no replacement; kept as is in "
                        f"{'step' if len(ids) == 1 else 'steps'} {', '.join(ids)}")
    if not steps:
        warnings.append(NO_STEPS)
    exported = [s for s in transcript.sources if source is None or s.id == source]
    spec = {
        "title": _fit(title or transcript.case or "Interlinear transcript", MAX_TITLE),
        "description": f"Exported by Interlinear {__version__} from {_source_names(exported)}. {ORDER_NOTE}",
        "authors": [],
        "steps": steps,
        "countermeasures": "auto",
        "max_countermeasures_per_step": 2,
    }
    return spec, warnings
