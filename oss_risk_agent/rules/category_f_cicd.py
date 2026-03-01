from pathlib import Path
from typing import List
import re
import yaml

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
                        if run_script and secret_pattern.search(run_script):
                            risks.append(RiskRecord(
                                category=self.category,
                                name=self.name,
                                severity=Severity.CRITICAL,
                                description=f"CIログ(workflow '{yaml_file.name}', job '{job_id}', step {step_idx+1}) に機密情報(secrets)が出力(echo等)されており、第三者に取得される可能性があります。",
                                target_file=str(yaml_file.relative_to(repo_path)),
                                evidence=secret_pattern.search(run_script).group(0)
                            ))
            except Exception:
                # YAMLのパースエラー等はスキップ
                pass
                
        return risks
