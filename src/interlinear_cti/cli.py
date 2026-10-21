"""Command-line interface for Interlinear.

Exit codes: 0 success, 1 success with warnings or rejected glosses, 2 invalid input or arguments, 3 an error writing
the transcript or an internal error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .errors import ResolverUnavailable
from .fileio import OutputError

MAX_PRINTED = 100  # rejections, and warnings, printed by apply-glosses and annotate; a glosses file can hold any number

# Writing an output failed, after the input was read: not invalid input, so exit code 3. It is fileio's error, so the
# commands that write through fileio (build-parse-pyz) are reported the same way. It holds the error's type name.
_OutputError = OutputError


def _escaped(text: str) -> str:
    """Text for the console that may hold attacker-chosen text (a path, an error message): defanged and escaped."""
    from .normalize import normalize_text
    from .parse import escape_controls

    return escape_controls(normalize_text(text), keep="")


def _save(transcript, path: str) -> None:
    from . import model

    try:
        model.save(transcript, path)
    except OSError as exc:  # such as a full disk
        raise _OutputError(type(exc).__name__) from None


def _by_label(value: str) -> str:
    from .glossing import BY_LABEL, BY_RULE

    if not BY_LABEL.fullmatch(value):
        raise argparse.ArgumentTypeError(f"must be a short label: {BY_RULE}")
    return value


def _at_least_one(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _utf8_stdio() -> None:
    """Write UTF-8 whatever the locale says (Windows pipes default to cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
        if encoding != "utf8" and hasattr(stream, "reconfigure"):
            # Keep the stream's error handler: reconfigure() with only an encoding resets it to "strict".
            stream.reconfigure(encoding="utf-8", errors=stream.errors)


def cmd_parse(args: argparse.Namespace) -> int:
    from .parse_main import run_safely

    return run_safely(args.files, args.output, kind=args.kind, case=args.case,
                      max_file_bytes=args.max_file_bytes, max_lines=args.max_lines,
                      max_retained_bytes=args.max_retained_bytes, max_files=args.max_files)


def cmd_build_parse_pyz(args: argparse.Namespace) -> int:
    from .pyz import build

    print(f"Wrote {build(args.output)}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from .rules import load_library, run_examples

    resolver = None
    if args.verify:
        from .verify import CountermapResolver

        resolver = CountermapResolver(args.db)
    try:
        library = load_library(resolver=resolver)
        if args.action == "list":
            for rule in library.rules:
                label = "context" if rule.context else ", ".join(rule.techniques)
                print(f"{rule.id:28} {label:24} {rule.file}")
            print(f"{_count(len(library.rules), 'rule', 'rules')}, version {library.version}")
            return 0
        failures = run_examples(library)
        for failure in failures:
            print(f"FAIL {failure}")
        checked = sum(len(r.examples_match) + len(r.examples_no_match) for r in library.rules)
        print(f"{_count(checked, 'example', 'examples')} checked, {_count(len(failures), 'failure', 'failures')}"
              + ("; techniques verified" if resolver else ""))
        return 1 if failures else 0
    finally:
        if resolver is not None:  # close the database connection, not leave it to the garbage collector
            resolver.close()


def _now() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_gloss(args: argparse.Namespace) -> int:
    from .glossing import apply_rules
    from .model import load
    from .rules import load_library
    from .verify import CountermapResolver

    transcript = load(args.transcript)
    with CountermapResolver(args.db) as resolver:
        library = load_library(resolver=resolver)
        counts = apply_rules(transcript, library, at=_now())
        transcript.datasets = resolver.versions()
    _save(transcript, args.transcript)
    pending = sum(1 for line in transcript.lines if line.gloss.source == "pending")
    partial = f" ({counts['partial']} partial, also left to the model)" if counts.get("partial") else ""
    print(f"Glossed {_escaped(args.transcript)} with rules {library.version}: "
          f"{counts.get('rule', 0)} rule{partial}, {counts.get('none', 0)} context; {pending} still pending")
    return 0


def cmd_pending(args: argparse.Namespace) -> int:
    from .glossing import pending_lines
    from .model import load

    rows = pending_lines(load(args.transcript), limit=args.limit, after=args.after,
                         redact_secrets=args.redact_secrets)
    print(json.dumps(rows, indent=1, ensure_ascii=False))
    return 0


def _read_glosses(path: str) -> list:
    """A glosses file: a JSON list, with or without the BOM Windows PowerShell 5.1 writes."""
    try:
        entries = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except RecursionError:
        raise ValueError(f"{path}: not a usable glosses file (JSON nested too deeply)") from None
    except ValueError as exc:  # not UTF-8, or not JSON
        raise ValueError(f"{path}: not a usable glosses file ({exc})") from None
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected a JSON list of gloss entries")
    return entries


def _merge_glosses(args: argparse.Namespace, source: str) -> int:
    from .glossing import apply_glosses
    from .model import load
    from .verify import CountermapResolver

    entries = _read_glosses(args.glosses)
    transcript = load(args.transcript)
    warnings: list[str] = []
    with CountermapResolver(args.db) as resolver:
        applied, rejected = apply_glosses(transcript, entries, source=source, by=args.by, resolver=resolver,
                                          at=_now(), warnings=warnings)
        if not transcript.datasets:
            transcript.datasets = resolver.versions()
    _save(transcript, args.transcript)
    glossed = _count(applied, f"{source} gloss", f"{source} glosses")
    summary = f"Applied {glossed} to {_escaped(args.transcript)}; rejected {len(rejected)}"
    print(summary + (f"; {_count(len(warnings), 'warning', 'warnings')}" if warnings else ""))
    _print_some(rejected, "rejected", "rejection", "rejections")
    _print_some(warnings, "warning", "warning", "warnings")
    return 1 if rejected or warnings else 0


def _count(n: int, one: str, many: str) -> str:
    """n and the noun that agrees with it: 1 line, 2 lines."""
    return f"{n} {one if n == 1 else many}"


def _print_some(messages: list[str], label: str, one: str, many: str) -> None:
    """Print the first MAX_PRINTED messages to stderr, then how many more there are (the summary counts them all)."""
    for message in messages[:MAX_PRINTED]:
        print(f"  {label}: {message}", file=sys.stderr)
    if len(messages) > MAX_PRINTED:
        print(f"  ... and {_count(len(messages) - MAX_PRINTED, f'more {one}', f'more {many}')}", file=sys.stderr)


def cmd_apply_glosses(args: argparse.Namespace) -> int:
    return _merge_glosses(args, "model")


def cmd_annotate(args: argparse.Namespace) -> int:
    return _merge_glosses(args, "analyst")


def _write_text(path: str | Path, text: str) -> None:
    """Write a text output file through fileio.atomic_write, which keeps a replaced file's mode, gives a new one the
    mode a plain create would, and removes its temporary file on any failure.

    A write-time OSError is signalled as _OutputError, which main() reports as exit code 3; anything else is raised as
    it is, so the UnicodeEncodeError of a lone surrogate in a hand-edited transcript is invalid input, exit code 2.
    """
    from . import fileio

    try:
        fileio.atomic_write(path, text)
    except OSError as exc:  # such as an unwritable folder or a full disk
        raise _OutputError(type(exc).__name__) from None


def _refuse_transcript(transcript: str, output: str | Path) -> None:
    """Refuse an output path that is the transcript itself, which the output would replace: invalid arguments."""
    import os

    try:
        same = os.path.samefile(transcript, output)
    except OSError:  # one of them does not exist
        same = Path(transcript).resolve() == Path(output).resolve()
    if same:
        raise ValueError(f"{output}: the output path is the transcript itself; choose another with -o")


MAX_HEADER_BYTES = 65536  # how much of an existing file's first line render reads to tell whether it wrote it
# File names and folder names that AI coding agents read as instructions, compared in lower case. The view holds
# attacker text, so render never writes one of these files, or anything under one of these folders, even a new one:
# the next agent session in that folder would load the attacker's text as its instructions.
AGENT_INSTRUCTION_NAMES = frozenset({
    "claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md", "conventions.md", ".cursorrules",
    ".claude", ".github", ".cursor", ".windsurf", ".amazonq", ".kiro", ".clinerules", ".roo", ".continue",
})


def _refuse_other_files(output: Path) -> None:
    """Refuse an agent instruction file, an output that is not a .md file, or an existing output that is not a
    regular file holding an earlier view: invalid arguments.

    The view holds attacker text, so render must not be aimed at a CLAUDE.md, a shell startup file or another
    transcript: it never writes a path an AI agent reads as instructions, writes only .md files, and replaces only a
    file whose first line is a view's header.
    """
    import os
    import stat

    from .render import is_render_header

    # The path as given and as resolved, so neither .. nor a working folder inside .claude gets past the check.
    parts = {part.lower() for part in (*output.parts, *output.resolve().parts)}
    if parts & AGENT_INSTRUCTION_NAMES:
        raise ValueError(f"{output}: AI agents read this path as agent instructions, so render will not write it")
    if output.suffix.lower() != ".md":
        raise ValueError(f"{output}: the output path must end in .md")
    try:
        st = os.stat(output)  # following a link, as reading the header would
    except (FileNotFoundError, NotADirectoryError):
        return  # nothing there yet
    except OSError as exc:  # such as a link loop or a folder that cannot be searched
        raise ValueError(f"{output}: cannot be checked ({type(exc).__name__}), so render will not replace it") from None
    # Opening a FIFO to read its first line would wait for a writer forever, and a device is no earlier view.
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{output}: exists and is not a regular file, so render will not replace it")
    try:
        # O_NONBLOCK where there is one: should a FIFO take the file's place after the check, the open still returns.
        fd = os.open(output, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "rb") as fh:
            first = fh.readline(MAX_HEADER_BYTES)
    except OSError:  # a file that cannot be read
        first = b""
    try:
        line = first.decode("utf-8-sig").rstrip("\r\n")  # an editor may have added a BOM or CRLF line endings
    except UnicodeDecodeError:
        line = ""
    if not is_render_header(line):
        raise ValueError(f"{output}: exists and is not an Interlinear render, so render will not replace it")


def cmd_render(args: argparse.Namespace) -> int:
    from .model import load
    from .render import render_markdown

    out = Path(args.output) if args.output else Path(args.transcript).with_suffix(".md")
    _refuse_transcript(args.transcript, out)
    _refuse_other_files(out)
    _write_text(out, render_markdown(load(args.transcript), redact_secrets=args.redact_secrets))
    print(f"Wrote {_escaped(str(out))}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .export import NO_STEPS, export_scenario
    from .model import load

    _refuse_transcript(args.transcript, args.output)
    spec, warnings = export_scenario(load(args.transcript), title=args.title)
    if not spec["steps"]:  # Countermap rejects a scenario with no steps, so none is written
        for warning in warnings:
            if warning != NO_STEPS:
                print(f"  warning: {_escaped(warning)}", file=sys.stderr)
        raise ValueError(f"{args.transcript}: {NO_STEPS}, so nothing was exported (a Countermap scenario needs at "
                         "least one step)")
    _write_text(args.output, json.dumps(spec, indent=2, ensure_ascii=False) + "\n")
    print(f"Wrote {_escaped(args.output)}: {_count(len(spec['steps']), 'step', 'steps')}")
    for warning in warnings:  # a warning can name a technique ID from a hand-edited transcript
        print(f"  warning: {_escaped(warning)}", file=sys.stderr)
    return 1 if warnings else 0


def build_parser() -> argparse.ArgumentParser:
    from .parse_main import SafeArgumentParser, add_parse_arguments

    # Subparsers take the parent's class, so every argument error is defanged and escaped.
    parser = SafeArgumentParser(prog="interlinear", description=__doc__)
    parser.add_argument("--version", action="version", version=f"interlinear {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("parse", help="stage 1: raw files to transcript.json (run inside the untrusted sandbox)")
    add_parse_arguments(p)
    p.set_defaults(func=cmd_parse)

    b = sub.add_parser("build-parse-pyz", help="build the standard-library-only parse zipapp for the sandbox")
    b.add_argument("-o", "--output", default="dist/interlinear-parse.pyz")
    b.set_defaults(func=cmd_build_parse_pyz)

    r = sub.add_parser("rules", help="list the rule library, or test its examples")
    r.add_argument("action", choices=["list", "test"])
    r.add_argument("--verify", action="store_true", help="also check every technique ID through Countermap")
    r.add_argument("--db", help="Countermap database (default: Countermap's default path)")
    r.set_defaults(func=cmd_rules)

    g = sub.add_parser("gloss", help="apply the rule library to pending lines")
    g.add_argument("transcript")
    g.add_argument("--db", help="Countermap database (default: Countermap's default path)")
    g.set_defaults(func=cmd_gloss)

    pe = sub.add_parser("pending", help="print pending lines as JSON, for the gloss skill")
    pe.add_argument("transcript")
    pe.add_argument("--limit", type=_at_least_one, default=50, metavar="N", help="at most N lines (default 50)")
    pe.add_argument("--after", type=int, default=0, metavar="N",
                    help="only lines numbered above N: pass the last n printed to get the next page (default 0)")
    pe.add_argument("--redact-secrets", action=argparse.BooleanOptionalAction, default=True,
                    help="replace passwords, tokens, keys and hashes in the text with <redacted KIND>, since this "
                         "output goes to a model (default; the transcript keeps them)")
    pe.set_defaults(func=cmd_pending)

    ap = sub.add_parser("apply-glosses", help="validate model glosses from a JSON file and fill pending lines")
    ap.add_argument("transcript")
    ap.add_argument("glosses")
    ap.add_argument("--by", required=True, type=_by_label, help="the model ID")
    ap.add_argument("--db", help="Countermap database (default: Countermap's default path)")
    ap.set_defaults(func=cmd_apply_glosses)

    an = sub.add_parser("annotate", help="validate analyst glosses from a JSON file and merge them; each replaces "
                                         "the line's earlier gloss, which moves to history")
    an.add_argument("transcript")
    an.add_argument("glosses")
    an.add_argument("--by", required=True, type=_by_label, help="your name")
    an.add_argument("--db", help="Countermap database (default: Countermap's default path)")
    an.set_defaults(func=cmd_annotate)

    rd = sub.add_parser("render", help="write the Markdown interlinear view")
    rd.add_argument("transcript")
    rd.add_argument("-o", "--output", help="default: the transcript path with .md")
    rd.add_argument("--redact-secrets", action="store_true",
                    help="replace passwords, tokens, keys and hashes in lines and glosses with <redacted KIND>, for a "
                         "view that will be shared (the transcript keeps them)")
    rd.set_defaults(func=cmd_render)

    ex = sub.add_parser("export-scenario", help="write a Countermap scenario spec from the glossed lines")
    ex.add_argument("transcript")
    ex.add_argument("-o", "--output", required=True)
    ex.add_argument("--title")
    ex.set_defaults(func=cmd_export)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run a command, with the error handling of parse_main.run_safely.

    An OSError or ValueError while reading the input (TranscriptError and LibraryError included) and an unavailable
    Countermap are invalid input: exit code 2, with the message defanged and escaped. An error writing an output (the
    transcript, a view, a scenario or the zipapp) is exit code 3, naming the error's type. Anything else, such as a database or YAML error, is an internal error:
    exit code 3, naming only the exception's type, since its message can carry attacker text.
    """
    args = build_parser().parse_args(argv)
    _utf8_stdio()
    try:
        return args.func(args)
    except _OutputError as exc:
        print(f"error: cannot write output ({exc})", file=sys.stderr)
        return 3
    except (OSError, ValueError, ResolverUnavailable) as exc:
        print(f"error: {_escaped(str(exc))}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - no traceback, which would print attacker text
        print(f"error: internal {type(exc).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
