"""Advisory data source client skeleton."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class VulnerabilitySignal:
    cve_id: str
    cvss: float | None = None
    epss_percentile: float | None = None
    kev_flag: bool = False
    exploit_available: bool = False


class AdvisoryClient:
    """Adapter over KEV / GHSA / OSV / NVD sources."""

    def lookup(self, package_name: str, version: str) -> list[VulnerabilitySignal]:
        """Return vulnerability signals for a dependency.

        TODO: implement source priority and merge policy.
        """
        _ = (package_name, version)
        return []
