"""Factory for mode-specific pipelines."""

from __future__ import annotations

from .base import Pipeline


def build_pipeline(mode: str) -> Pipeline:
    """Create pipeline for given mode.

    TODO: return dedicated subclasses once implemented.
    """
    return Pipeline(mode=mode)
