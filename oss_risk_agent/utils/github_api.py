import httpx
import re
import os
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
from cachetools import cached, TTLCache

# Caches for GitHub API calls
_gh_repo_cache = TTLCache(maxsize=100, ttl=3600)
_gh_contributors_cache = TTLCache(maxsize=100, ttl=3600)
_gh_scorecard_cache = TTLCache(maxsize=100, ttl=3600)

def _get_github_headers() -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers

def get_github_repo_from_git_config(repo_path: Path) -> Optional[str]:
    """ローカルの.git/configからGitHubのリポジトリ名(owner/repo)を抽出する"""
    git_config = repo_path / ".git" / "config"
    if not git_config.exists():
        return None
        
    try:
        with open(git_config, "r", encoding="utf-8") as f:
            content = f.read()
            match = re.search(r'url\s*=\s*(?:https://github\.com/|git@github\.com:)([^/]+/[^\.]+)', content)
            if match:
                # Remove .git translation
                repo_str = match.group(1)
                if repo_str.endswith(".git"):
                    repo_str = repo_str[:-4]
                return repo_str
    except Exception:
        pass
    return None

@cached(cache=_gh_repo_cache)
@retry(
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
    reraise=False
)
def fetch_github_repository_info(owner_repo: str) -> Optional[Dict[str, Any]]:
    """リポジトリの基本情報（最終更新日など）を取得する"""
    url = f"https://api.github.com/repos/{owner_repo}"
    
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url, headers=_get_github_headers())
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 403 and "rate_limit" in resp.text:
                raise httpx.RequestError("GitHub API Rate Limited")
    except Exception:
        pass
    return None

@cached(cache=_gh_contributors_cache)
@retry(
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
    reraise=False
)
def fetch_github_contributors(owner_repo: str) -> List[Dict[str, Any]]:
    """コントリビューターのリストとそれぞれのコミット数を取得する"""
    url = f"https://api.github.com/repos/{owner_repo}/contributors"
    
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{url}?per_page=100", headers=_get_github_headers())
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 403 and "rate_limit" in resp.text:
                raise httpx.RequestError("GitHub API Rate Limited")
    except Exception:
        pass
    return []

def is_repo_abandoned(owner_repo: str, months_threshold: int = 12) -> Tuple[bool, Optional[str]]:
    """最終コミットが指定された月数より前かどうかを判定する"""
    info = fetch_github_repository_info(owner_repo)
    if not info:
        return False, None
        
    # pushed_atが最後にコードがプッシュされた日時
    pushed_at_str = info.get("pushed_at")
    if not pushed_at_str:
        return False, None
        
    # YYYY-MM-DDTHH:MM:SSZ
    try:
        pushed_at = datetime.fromisoformat(pushed_at_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff_days = (now - pushed_at).days
        
        if diff_days > months_threshold * 30:
            return True, pushed_at_str
        return False, pushed_at_str
    except Exception:
        return False, None

def check_bus_factor(owner_repo: str, threshold_ratio: float = 0.8) -> Tuple[bool, Optional[str]]:
    """トップコントリビューターが総コミットの threshold_ratio 以上を占めるか判定する"""
    contributors = fetch_github_contributors(owner_repo)
    if not contributors:
        return False, None
        
    total_commits = sum(c.get("contributions", 0) for c in contributors)
    if total_commits == 0:
        return False, None
        
    top_contributor = contributors[0]
    top_commits = top_contributor.get("contributions", 0)
    top_name = top_contributor.get("login", "Unknown")
    
    ratio = top_commits / total_commits
    if ratio >= threshold_ratio:
        return True, f"{top_name} ({ratio:.1%} のコミットを占有)"
        
    return False, None

@cached(cache=_gh_repo_cache)
@retry(
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
    reraise=False
)
def check_branch_protection(owner_repo: str, branch: str = "main") -> Tuple[bool, str]:
    """
    指定ブランチ（主にmain/master）のブランチ保護ルールが有効か確認する。
    ※リポジトリの管理者権限または適切なアクセス権を持つトークンが必要
    """
    url = f"https://api.github.com/repos/{owner_repo}/branches/{branch}/protection"
    
    headers = _get_github_headers()
    if "Authorization" not in headers:
        return False, "GITHUB_TOKEN未設定のためブランチ保護設定を取得できません"
        
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                if "required_pull_request_reviews" in data:
                    return True, f"{branch}ブランチ保護: 有効 (レビュー必須)"
                return True, f"{branch}ブランチ保護: 有効 (部分的な保護)"
            elif resp.status_code == 404:
                return False, f"{branch}ブランチ保護: 無効 (未設定)"
            elif resp.status_code in [403, 401]:
                if "rate_limit" in resp.text:
                    raise httpx.RequestError("GitHub API Rate Limited")
                return False, f"アクセス権限不足 ({resp.status_code})"
    except Exception as e:
        return False, f"APIリクエストエラー: {str(e)}"
        
    return False, "取得失敗"

@cached(cache=_gh_repo_cache)
@retry(
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
    reraise=False
)
def has_security_policy(owner_repo: str) -> bool:
    """ SECURITY.md ポリシーファイルが存在するか確認する """
    url = f"https://api.github.com/repos/{owner_repo}/contents/SECURITY.md"
    
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.head(url, headers=_get_github_headers())
            if resp.status_code == 200:
                return True
            elif resp.status_code == 403 and "rate_limit" in resp.text:
                 raise httpx.RequestError("GitHub API Rate Limited")
    except Exception:
        pass
    return False

@cached(cache=_gh_scorecard_cache)
@retry(
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
    reraise=False
)
def get_openssf_scorecard(owner_repo: str) -> Optional[Dict[str, Any]]:
    """ 指定リポジトリのOpenSSF Scorecard結果を取得する """
    url = f"https://api.securityscorecards.dev/projects/github.com/{owner_repo}"
    
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                raise httpx.RequestError("Scorecard API Rate Limited")
    except Exception:
        pass
    return None

