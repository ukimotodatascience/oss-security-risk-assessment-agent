from pathlib import Path
from typing import List
import re
import yaml
import math
from collections import Counter

from ..core.models import Rule, RiskRecord, Severity


class F1SecretsLogOutputRule(Rule):
    @property
    def category(self) -> str:
        return "F-1"

    @property
    def name(self) -> str:
        return "secretsのログ出力"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        workflows_dir = repo_path / ".github" / "workflows"
        if not workflows_dir.exists() or not workflows_dir.is_dir():
            return risks

        # echo や print などの標準出力コマンドの引数に secrets が含まれているか（正規表現チェック）
        secret_pattern = re.compile(r"echo.*?\${{\s*secrets\.[a-zA-Z0-9_]+\s*}}")

        for yaml_file in workflows_dir.glob("*.yml"):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    workflow_data = yaml.safe_load(f)

                if not isinstance(workflow_data, dict) or "jobs" not in workflow_data:
                    continue

                jobs = workflow_data.get("jobs", {})
                for job_id, job_data in jobs.items():
                    steps = job_data.get("steps", [])
                    for step_idx, step in enumerate(steps):
                        run_script = step.get("run", "")
                        match = (
                            secret_pattern.search(run_script) if run_script else None
                        )
                        if match:
                            risks.append(
                                RiskRecord(
                                    category=self.category,
                                    name=self.name,
                                    severity=Severity.CRITICAL,
                                    description=f"CIログ(workflow '{yaml_file.name}', job '{job_id}', step {step_idx + 1}) に機密情報(secrets)が出力(echo等)されており、第三者に取得される可能性があります。",
                                    target_file=str(yaml_file.relative_to(repo_path)),
                                    evidence=match.group(0),
                                )
                            )
            except Exception:
                # YAMLのパースエラー等はスキップ
                pass

        return risks


class F2StructuredTokenDetectionRule(Rule):
    @property
    def category(self) -> str:
        return "F-2"

    @property
    def name(self) -> str:
        return "構造化トークン検出"

    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        n = len(text)
        ent = 0.0
        for c in counts.values():
            p = c / n
            ent -= p * math.log2(p)
        return ent

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks: List[RiskRecord] = []

        patterns = {
            "AWS Access Key": re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
            "GitHub PAT": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", re.IGNORECASE),
            "Slack Token": re.compile(
                r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", re.IGNORECASE
            ),
            "GCP Service Key": re.compile(r'"type"\s*:\s*"service_account"'),
        }

        target_files = []
        target_files.extend(repo_path.rglob("*.py"))
        target_files.extend(repo_path.rglob("*.js"))
        target_files.extend(repo_path.rglob("*.ts"))
        target_files.extend(repo_path.rglob("*.json"))
        target_files.extend(repo_path.rglob("*.yml"))
        target_files.extend(repo_path.rglob("*.yaml"))
        target_files.extend(repo_path.rglob("*.env"))
        target_files = list(dict.fromkeys(target_files))

        for file in target_files:
            if ".git" in file.parts or "node_modules" in file.parts:
                continue
            try:
                with open(file, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        stripped = line.strip()
                        if not stripped:
                            continue

                        for token_type, pattern in patterns.items():
                            m = pattern.search(stripped)
                            if not m:
                                continue

                            token = m.group(0)
                            ent = self._entropy(token)
                            # 正規表現 + 高エントロピー併用
                            # GCP service key marker is structured JSON and may have low entropy.
                            if token_type != "GCP Service Key" and ent < 3.5:
                                continue

                            risks.append(
                                RiskRecord(
                                    category=self.category,
                                    name=self.name,
                                    severity=Severity.CRITICAL,
                                    description=f"{token_type} 形式のトークンが検出されました。",
                                    target_file=str(file.relative_to(repo_path)),
                                    line_number=i,
                                    evidence=token[:12] + "...",
                                )
                            )
            except (OSError, UnicodeDecodeError):
                continue

        return risks
