"""Check technique IDs against the loaded ATT&CK and ATLAS data through Countermap."""

from __future__ import annotations

import re
import sqlite3
from typing import Protocol

from .errors import ResolverUnavailable
from .model import Technique

__all__ = ["CANONICAL_ID", "INSTALL_HINT", "CountermapResolver", "Resolver", "ResolverUnavailable", "framework_of"]

# pipx and uv put only Interlinear's own command on PATH, so their forms also ask for Countermap's, which builds the
# database. One line, because the CLI escapes newlines in error messages.
INSTALL_HINT = (
    "Countermap is not installed. Install Interlinear with its countermap extra, then build Countermap's database once"
    " with `countermap build`."
    " With pipx: pipx install 'interlinear-cti[countermap]',"
    " then pipx inject --include-apps --force interlinear-cti 'countermap>=0.2,<0.3'."
    " With uv: uv tool install 'interlinear-cti[countermap]' --with-executables-from countermap."
    " With pip, in a virtual environment: pip install 'interlinear-cti[countermap]'."
)

# The only references ever looked up: an ATT&CK or ATLAS technique or sub-technique ID, after stripping and
# upper-casing. Names, namespaced references (attack:T1105) and the other ID families (groups, software, tactics,
# mitigations, campaigns, ATLAS case studies, D3FEND) are unknown without asking Countermap, which would resolve
# each of them to some node.
CANONICAL_ID = re.compile(r"(?:AML\.)?T\d{4}(?:\.\d{3})?", re.ASCII)
_FRAMEWORKS = ("attack", "atlas")


class Resolver(Protocol):
    def check(self, technique_id: str) -> Technique: ...

    def versions(self) -> dict[str, str]: ...


def framework_of(technique_id: str) -> str:
    return "atlas" if technique_id.strip().upper().startswith("AML.") else "attack"


class CountermapResolver:
    """Countermap's technique lookups. It holds an open SQLite connection: use it as a context manager, or call
    close(), so the connection is closed when the caller is done and not left to the garbage collector."""

    def __init__(self, db_path: str | None = None) -> None:
        try:
            from countermap.query import Countermap, NotFound
            from countermap.sources import default_db_path
        except ImportError as exc:
            raise ResolverUnavailable(INSTALL_HINT) from exc
        path = db_path or default_db_path()
        self._c = None
        try:
            self._c = Countermap(path)
            # Read the database now, so an empty, corrupt or unreadable one fails here and not in the first check.
            self._versions = self._c.source_versions()
        except FileNotFoundError as exc:
            raise ResolverUnavailable(str(exc)) from exc
        except sqlite3.Error as exc:
            self.close()
            raise ResolverUnavailable(
                f"{path} is not a usable Countermap database ({exc}). Rebuild it with `countermap build`."
            ) from exc
        self._not_found = NotFound
        self._cache: dict[str, Technique] = {}

    def close(self) -> None:
        """Close the database connection. Safe to call more than once; a check that needs the database after it
        raises ResolverUnavailable."""
        if self._c is not None:
            # Countermap opens one connection per thread on first use of .conn and has no close() of its own;
            # every call here runs on the caller's thread, so .conn is the one connection opened.
            self._c.conn.close()
            self._c = None

    def __enter__(self) -> CountermapResolver:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def check(self, technique_id: str) -> Technique:
        if not isinstance(technique_id, str):  # None or any other non-string is not an ID
            return Technique(id="", framework="attack", status="unknown")
        key = technique_id.strip().upper()
        if not CANONICAL_ID.fullmatch(key):
            return Technique(id=key, framework=framework_of(key), status="unknown")
        if key not in self._cache:
            self._cache[key] = self._lookup(key)
        return self._cache[key].model_copy(deep=True)

    def _lookup(self, key: str) -> Technique:
        if self._c is None:
            raise ResolverUnavailable("the Countermap resolver is closed")
        unknown = Technique(id=key, framework=framework_of(key), status="unknown")
        try:
            node_id = self._c.parse_ref(key, framework=framework_of(key), kind="technique")
            info = self._c.lookup(node_id, desc_chars=0)
        except self._not_found:
            return unknown
        framework, _, ext_id = node_id.partition(":")
        # lookup() follows revocations, so for a revoked technique with a replacement it describes the replacement.
        if framework not in _FRAMEWORKS or info.get("kind") != "technique":
            return unknown
        resolved = self._c.resolve(node_id)
        if resolved["changed"]:
            return Technique(id=ext_id, framework=framework, status="revoked",
                             replaced_by=[resolved["id"].partition(":")[2]])
        if info.get("revoked"):  # revoked with no replacement in the loaded data
            return Technique(id=ext_id, framework=framework, status="revoked")
        status = "deprecated" if info.get("deprecated") else "active"
        return Technique(id=ext_id, framework=framework, status=status, name=info.get("name"))

    def versions(self) -> dict[str, str]:
        wanted = ("attack-enterprise", "attack-mobile", "attack-ics", "atlas")
        return {k: str(v) for k, v in self._versions.items() if k in wanted and v}
