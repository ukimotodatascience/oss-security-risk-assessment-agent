"""GitHub API client skeleton for governance metrics."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class RepoHealth:
    last_commit_days_ago: int | None = None
    bus_factor: int | None = None
    has_security_policy: bool | None = None


class GitHubClient:
    def get_repo_health(self, owner: str, repo: str) -> RepoHealth:
        """Fetch governance signals.

        TODO: integrate GitHub REST/GraphQL with auth and cache.
        """
        _ = (owner, repo)
        return RepoHealth()
