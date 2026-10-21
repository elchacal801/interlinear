"""The one atomic writer for files Interlinear writes (spec section 10). Standard library only: the parse stage's zipapp
includes this module.

A file is written to a temporary file in the same folder and renamed over the target with os.replace, so a reader
sees the old file or the new one, never a partial one, and a failed write leaves the old file as it was.
"""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path


class OutputError(Exception):
    """Writing an output file failed. That is not invalid input, so a command exits with code 3. The message is only
    the underlying error's type name, since an error message can hold an attacker-chosen path."""


def file_mode(path: str | Path) -> int:
    """The mode for a file written to path through a temporary file: the mode of the regular file it replaces, or
    else the mode a plain create would give it, 0o666 less the umask. On Windows only the read-only flag applies."""
    try:
        st = os.stat(path)
    except OSError:  # nothing there yet
        st = None
    if st is not None and stat.S_ISREG(st.st_mode):
        return stat.S_IMODE(st.st_mode)
    # The umask can only be read by setting it, so set an owner-only one and restore the old one straight away: a
    # file or folder another thread creates in between is never more open than it would have been.
    umask = os.umask(0o077)
    os.umask(umask)
    return 0o666 & ~umask


def discard_temp(tmp: str | Path) -> None:
    """Remove a temporary file after a failed write, without hiding the failure. Windows cannot remove a read-only
    file, which a temporary file given a read-only file's mode is, so it is made writable first."""
    with contextlib.suppress(OSError):
        os.chmod(tmp, stat.S_IREAD | stat.S_IWRITE)
    with contextlib.suppress(OSError):
        Path(tmp).unlink(missing_ok=True)


def atomic_write(path: str | Path, data: bytes | str | Iterable[str], executable: bool = False) -> Path:
    """Write data to path atomically, creating missing folders, and return the path.

    data is bytes, or text written as UTF-8 with no newline translation, so a file is byte-identical on Windows and
    Linux. It may also be an iterable of text chunks, such as json.JSONEncoder.iterencode gives, so a large file is
    never held whole. A new file gets the mode a plain create would give it (0o666 less the umask) and a replaced file
    keeps its mode (file_mode); executable adds the owner's execute bit. On any exception the temporary file is
    removed (discard_temp) and the exception is raised again, an OSError as it came.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = file_mode(p) | (stat.S_IXUSR if executable else 0)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            if isinstance(data, bytes):
                fh.write(data)
            elif isinstance(data, str):
                fh.write(data.encode("utf-8"))
            else:
                for chunk in data:
                    fh.write(chunk.encode("utf-8"))
        os.chmod(tmp, mode)  # mkstemp creates the file 0o600
        os.replace(tmp, p)
    except BaseException:
        discard_temp(tmp)
        raise
    return p
