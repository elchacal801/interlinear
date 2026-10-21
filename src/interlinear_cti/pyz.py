"""Build the standard-library-only parse zipapp that runs inside a sandbox."""

from __future__ import annotations

import io
import shutil
import tempfile
import zipapp
from pathlib import Path

from .fileio import OutputError, atomic_write

PACKAGE = Path(__file__).resolve().parent
PARSE_FILES = ("__init__.py", "decode.py", "fileio.py", "parse.py", "parse_main.py", "normalize.py", "textshow.py",
               "tlds.py")


def build(output: str | Path) -> Path:
    """Build the zipapp into memory, then write it atomically (fileio.atomic_write), executable by its owner.

    Any OSError, such as a full disk or an output folder that is a file, raises OutputError, which is exit code 3:
    the build failed, not the input. The old file, if any, is left as it was.
    """
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "interlinear_cti"
            target.mkdir()
            for name in PARSE_FILES:
                shutil.copy2(PACKAGE / name, target / name)
            shutil.copytree(PACKAGE / "readers", target / "readers", ignore=shutil.ignore_patterns("__pycache__"))
            archive = io.BytesIO()
            zipapp.create_archive(tmp, archive, interpreter="/usr/bin/env python3",
                                  main="interlinear_cti.parse_main:main_exit")
        return atomic_write(output, archive.getvalue(), executable=True)
    except OSError as exc:
        raise OutputError(type(exc).__name__) from None
