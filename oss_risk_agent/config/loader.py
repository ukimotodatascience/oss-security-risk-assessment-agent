"""Configuration loader skeleton.

Concrete YAML/TOML parsing will be implemented later.
"""

from __future__ import annotations

from pathlib import Path

from .settings import RuntimeConfig


class ConfigLoader:
    def __init__(self, root: Path) -> None:
        self.root = root

    def load(self) -> RuntimeConfig:
        """Load runtime config from repository.

        TODO:
        - Parse .oss-risk-policy.yml
        - Parse .oss-risk-ignore.yml
        - Validate required fields and defaults
        """
        return RuntimeConfig()
