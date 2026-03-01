from __future__ import annotations

import os
from functools import lru_cache
from typing import Set


@lru_cache(maxsize=1)
def _load_kev_from_env() -> Set[str]:
    raw = os.environ.get("OSS_RISK_KEV_CVES", "")
    if not raw:
        return set()
    return {v.strip().upper() for v in raw.split(",") if v.strip()}


def is_known_exploited(cve_id: str) -> bool:
    if not cve_id:
        return False
    return cve_id.upper() in _load_kev_from_env()
