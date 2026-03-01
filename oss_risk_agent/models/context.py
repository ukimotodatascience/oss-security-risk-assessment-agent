"""Scan context model.

Only structure is defined for now. Business logic will be implemented later.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ScanContext:
    deployment_type: str = "vm"
    internet_exposed: bool = True
    data_sensitivity: str = "medium"
    environment: str = "production"
    assumption: str | None = None
