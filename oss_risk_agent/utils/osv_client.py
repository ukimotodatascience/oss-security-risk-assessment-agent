import httpx
from typing import Dict, Any, Optional
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
from cachetools import cached, TTLCache

OSV_API_URL = "https://api.osv.dev/v1/query"

# Cache for 1 hour, max 1000 items
_osv_cache = TTLCache(maxsize=1000, ttl=3600)

@cached(cache=_osv_cache)
@retry(
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
    reraise=False
)
def check_vulnerability(package_name: str, version: str, ecosystem: str = "PyPI") -> Optional[Dict[str, Any]]:
    """
    OSV.devのAPIを利用して、指定されたパッケージとバージョンが脆弱性データベースに存在するかチェックする。
    脆弱性が存在する場合はその詳細を含むJSONを返し、存在しない場合はNoneを返す。
    ecosystem: 'PyPI', 'npm', etc.
    リトライ機構とキャッシュによりAPI呼び出しを最適化。
    """
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(OSV_API_URL, json=payload)
            if response.status_code == 200:
                data = response.json()
                if "vulns" in data and len(data["vulns"]) > 0:
                    return data
            elif response.status_code == 429:
                # Rate limited, raise exception to trigger retry
                raise httpx.RequestError("OSV API Rate Limited")
                
            return None
    except Exception as e:
        print(f"OSV API Error for {package_name}@{version}: {e}")
        return None
