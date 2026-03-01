from pathlib import Path
from typing import List

from ..core.models import Rule, RiskRecord, Severity
from ..utils.github_api import get_github_repo_from_git_config, is_repo_abandoned, check_bus_factor

class D1AbandonedRepoRule(Rule):
    @property
    def category(self) -> str:
        return "D-1"

    @property
    def name(self) -> str:
        return "更新停止"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        owner_repo = get_github_repo_from_git_config(repo_path)
        if not owner_repo:
            return risks
            
        abandoned, last_push = is_repo_abandoned(owner_repo, months_threshold=12)
        if abandoned:
            risks.append(RiskRecord(
                category=self.category,
                name=self.name,
                severity=Severity.HIGH,
                description=f"リポジトリ '{owner_repo}' は12ヶ月以上更新されていません（新たな脆弱性に対応されない可能性があります）。",
                target_file="GitHub API",
                evidence=f"Last pushed: {last_push}"
            ))
            
        return risks

class D2BusFactorRule(Rule):
    @property
    def category(self) -> str:
        return "D-2"

    @property
    def name(self) -> str:
        return "Bus Factor 1"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        owner_repo = get_github_repo_from_git_config(repo_path)
        if not owner_repo:
            return risks
            
        is_bus_factor_1, evidence = check_bus_factor(owner_repo, threshold_ratio=0.8)
        if is_bus_factor_1:
            risks.append(RiskRecord(
                category=self.category,
                name=self.name,
                severity=Severity.MEDIUM,
                description=f"リポジトリ '{owner_repo}' の主要なコミットの大半を単一の開発者が担っており、継続性が低い状態です。",
                target_file="GitHub API",
                evidence=evidence or "Bus Factor 1 状態"
            ))
            
        return risks

class D3BranchProtectionRule(Rule):
    @property
    def category(self) -> str:
        return "D-3"

    @property
    def name(self) -> str:
        return "ブランチ保護が無効"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        owner_repo = get_github_repo_from_git_config(repo_path)
        if not owner_repo:
            return risks
            
        from ..utils.github_api import check_branch_protection
        # 簡易的に "main" ブランチを想定
        is_protected, msg = check_branch_protection(owner_repo, branch="main")
        if not is_protected:
            risks.append(RiskRecord(
                category=self.category,
                name=self.name,
                severity=Severity.MEDIUM,
                description=f"リポジトリ '{owner_repo}' の main ブランチに保護ルールが設定されていません (OpenSSF Scorecard要件)。",
                target_file="GitHub API",
                evidence=msg
            ))
            
        return risks

class D4SecurityPolicyRule(Rule):
    @property
    def category(self) -> str:
        return "D-4"

    @property
    def name(self) -> str:
        return "セキュリティポリシー未定義"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        owner_repo = get_github_repo_from_git_config(repo_path)
        if not owner_repo:
            return risks
            
        from ..utils.github_api import has_security_policy
        has_policy = has_security_policy(owner_repo)
        
        # まずローカルにあるかチェックする
        local_policy = repo_path / "SECURITY.md"
        local_policy_hidden = repo_path / ".github" / "SECURITY.md"
        
        has_local = local_policy.exists() or local_policy_hidden.exists()

        if not has_policy and not has_local:
            risks.append(RiskRecord(
                category=self.category,
                name=self.name,
                severity=Severity.LOW,
                description=f"リポジトリ '{owner_repo}' に SECURITY.md が存在せず、脆弱性報告のプロセスが不明確です (OpenSSF Scorecard要件)。",
                target_file="GitHub API / Local Repository",
                evidence="SECURITY.md が見つかりません"
            ))
            
        return risks

class D5OpenSSFScorecardRule(Rule):
    @property
    def category(self) -> str:
        return "D-5"

    @property
    def name(self) -> str:
        return "OpenSSF Scorecard 低スコア"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        owner_repo = get_github_repo_from_git_config(repo_path)
        if not owner_repo:
            return risks
            
        from ..utils.github_api import get_openssf_scorecard
        scorecard = get_openssf_scorecard(owner_repo)
        
        if scorecard:
            score = scorecard.get("score")
            # scoreが取れており、特定のしきい値(例: 5.0/10.0未満)の場合はリスクとして報告
            if score is not None and score < 5.0:
                checks = scorecard.get("checks", [])
                failed_checks = [c.get("name") for c in checks if c.get("score", 10) < 5]
                
                risks.append(RiskRecord(
                    category=self.category,
                    name=self.name,
                    severity=Severity.HIGH,
                    description=f"リポジトリ '{owner_repo}' の OpenSSF Scorecard スコアが {score}/10 と低く、持続可能性やセキュリティ運用ベストプラクティスが満たされていません。",
                    target_file="OpenSSF Scorecard API",
                    evidence=f"課題が多い項目: {', '.join(failed_checks[:3])} など"
                ))
            
        return risks
