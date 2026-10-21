"""Errors shared across stages.

Standard library only: the CLI imports this module on every run, and `interlinear parse` must not load pydantic.
"""

from __future__ import annotations


class ResolverUnavailable(RuntimeError):
    """Countermap or its database is missing or unusable."""
