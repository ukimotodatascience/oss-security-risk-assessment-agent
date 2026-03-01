"""External integrations (advisory DB, VCS, policy engines)."""

from .advisory_client import AdvisoryClient
from .github_client import GitHubClient

__all__ = ["AdvisoryClient", "GitHubClient"]
