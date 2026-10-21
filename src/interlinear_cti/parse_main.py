"""Standalone entry point for the parse stage (the sandbox zipapp and `interlinear parse`). Standard library only.

Exit codes: 0 success, 1 success with warnings, 2 invalid input or arguments, 3 internal error.
"""

from __future__ import annotations

import argparse
import errno
import os
import sys

from .normalize import normalize_text
from .parse import (
    KINDS,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_LINES,
    MAX_RETAINED_BYTES,
    escape_controls,
    parse_paths,
    write_transcript,
)

MAX_PRINTED_WARNINGS = 100  # warnings printed to the console; the transcript holds them all


class _OutputError(Exception):
    """Writing the transcript failed, after the input was read: not invalid input. Holds the error's type name."""


class SafeArgumentParser(argparse.ArgumentParser):
    """An argument parser whose error messages are defanged and escaped, since they can quote a hostile file name."""

    def error(self, message: str):
        super().error(escape_controls(normalize_text(message), keep=""))


def add_parse_arguments(parser: argparse.ArgumentParser) -> None:
    """The parse stage's arguments, shared by the zipapp and `interlinear parse`."""
    parser.add_argument("files", nargs="+", help="history files, scripts, agent logs, or folders of them")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--kind", default="auto", choices=KINDS)
    parser.add_argument("--case")
    parser.add_argument("--max-file-bytes", type=int, default=MAX_FILE_BYTES, metavar="N",
                        help=f"record larger files by hash only (default {MAX_FILE_BYTES}, which is 8 MiB)")
    parser.add_argument("--max-lines", type=int, default=MAX_LINES, metavar="N",
                        help=f"stop adding lines after N, and record the rest by hash only (default {MAX_LINES})")
    parser.add_argument("--max-retained-bytes", type=int, default=MAX_RETAINED_BYTES, metavar="N",
                        help="stop adding lines once their text would pass N bytes, and record the rest by hash only "
                             f"(default {MAX_RETAINED_BYTES}, which is 256 MiB)")
    parser.add_argument("--max-files", type=int, default=MAX_FILES, metavar="N",
                        help=f"record at most N files, and only count the rest (default {MAX_FILES})")


def run(files: list[str], output: str, kind: str = "auto", case: str | None = None,
        max_file_bytes: int = MAX_FILE_BYTES, max_lines: int = MAX_LINES,
        max_retained_bytes: int = MAX_RETAINED_BYTES, max_files: int = MAX_FILES) -> int:
    if os.path.isdir(output):  # an invalid argument, found before any input is read
        raise IsADirectoryError(errno.EISDIR, "the output path is a folder", str(output))
    data = parse_paths(files, kind=kind, case=case, max_file_bytes=max_file_bytes, max_lines=max_lines,
                       max_retained_bytes=max_retained_bytes, max_files=max_files)
    try:
        write_transcript(data, output)
    except OSError as exc:  # such as a full disk
        raise _OutputError(type(exc).__name__) from None
    # parse_paths escapes names and warnings, and the output path is escaped here, so nothing raw is printed.
    print(f"Wrote {escape_controls(str(output), keep='')}: {len(data['lines'])} lines "
          f"from {len(data['sources'])} file(s)")
    for warning in data["warnings"][:MAX_PRINTED_WARNINGS]:
        print(f"  warning: {warning}", file=sys.stderr)
    unprinted = len(data["warnings"]) - MAX_PRINTED_WARNINGS
    if unprinted > 0:
        print(f"  and {unprinted} more warning(s) in the transcript", file=sys.stderr)
    return 1 if data["warnings"] else 0


def run_safely(files: list[str], output: str, **options) -> int:
    """run(), with the error handling that the zipapp and `interlinear parse` share.

    An OSError or ValueError while reading the input, such as a missing input or an output path that is a folder, is
    invalid input: exit code 2, with its message defanged and escaped, since it can hold an attacker-chosen path. An
    error writing the transcript, such as a full disk, is exit code 3, naming the error's type. Anything else is an
    internal error: exit code 3, naming only the exception's type, since its message can carry attacker text.
    """
    try:
        return run(files, output, **options)
    except _OutputError as exc:
        print(f"error: cannot write output ({exc})", file=sys.stderr)
        return 3
    except (OSError, ValueError) as exc:
        print(f"error: {escape_controls(normalize_text(str(exc)), keep='')}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - no traceback, which would print attacker text
        print(f"error: internal {type(exc).__name__}", file=sys.stderr)
        return 3


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(prog="interlinear-parse", description="Parse raw transcripts into transcript.json.")
    add_parse_arguments(parser)
    args = parser.parse_args(argv)
    return run_safely(args.files, args.output, kind=args.kind, case=args.case,
                      max_file_bytes=args.max_file_bytes, max_lines=args.max_lines,
                      max_retained_bytes=args.max_retained_bytes, max_files=args.max_files)


def main_exit() -> None:
    sys.exit(main())
