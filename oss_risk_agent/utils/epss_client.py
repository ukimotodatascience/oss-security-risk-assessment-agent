import requests
from typing import Optional, Dict
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
from cachetools import cached, TTLCache

# Cache for 1 hour, max 2000 items
_epss_cache = TTLCache(maxsize=2000, ttl=3600)

@cached(cache=_epss_cache)
@retry(
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type((requests.RequestException, requests.Timeout)),
    reraise=False
)
def get_epss_score(cve_id: str) -> Optional[float]:
    """
    指定されたCVEのEPSSスコア（0.0 〜 1.0）を取得する。
    FIRST EPSS API を使用: https://api.first.org/epss
    リトライ機構とキャッシュによりAPI呼び出しを最適化。
    """
    url = f"https://api.first.org/epss?cve={cve_id}"
    try:
        response = requests.get(url, timeout=10.0)
        
        if response.status_code == 429:
             # Rate limited, raise to retry
             raise requests.RequestException("EPSS API Rate Limited")
             
        response.raise_for_status()
        data = response.json()
        
        if data.get("data") and len(data["data"]) > 0:
            epss_str = data["data"][0].get("epss")
            if epss_str:
                return float(epss_str)
    except Exception:
        pass
        
    return None
