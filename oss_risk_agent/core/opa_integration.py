from pathlib import Path
from typing import List, Dict, Any
import json
import shutil
import subprocess
import tempfile

from ..core.models import Rule, RiskRecord, Severity


class OPAIntegrationEngine:
    """
    Open Policy Agent (OPA) / Rego との連携を想定したポリシー評価エンジンのスタブです。
    将来的に、各種設定ファイル(JSON/YAML)をOPAの入力形式に変換し、事前に定義された
    Regoポリシー（例: policy/security.rego）と照合するインターフェースを提供します。
    """

    def __init__(self, policy_dir: Path):
        self.policy_dir = policy_dir

    def _to_severity(self, value: Any, default: Severity = Severity.HIGH) -> Severity:
        if not value:
            return default
        try:
            return Severity(str(value).upper())
        except ValueError:
            return default

    def _record_from_violation(
        self, violation: Any, policy_name: str, default_severity: Severity
    ) -> RiskRecord:
        if isinstance(violation, dict):
            msg = (
                violation.get("msg")
                or violation.get("message")
                or violation.get("description")
                or "OPAポリシー違反を検出しました"
            )
            name = violation.get("name") or f"OPA Policy Violation ({policy_name})"
            severity = self._to_severity(
                violation.get("severity"), default=default_severity
            )
            target_file = (
                violation.get("target_file")
                or violation.get("file")
                or violation.get("path")
                or "[OPA Policy Input]"
            )
            line_number = violation.get("line_number") or violation.get("line")
            evidence = violation.get("evidence") or json.dumps(
                violation, ensure_ascii=False
            )
        else:
            msg = str(violation)
            name = f"OPA Policy Violation ({policy_name})"
            severity = default_severity
            target_file = "[OPA Policy Input]"
            line_number = None
            evidence = str(violation)

        return RiskRecord(
            category="G-1",
            name=name,
            severity=severity,
            description=msg,
            target_file=target_file,
            line_number=line_number,
            evidence=evidence,
            score_metadata={"policy": policy_name},
        )

    def _extract_risks_from_value(
        self, value: Any, policy_name: str
    ) -> List[RiskRecord]:
        risks: List[RiskRecord] = []

        if value is None or isinstance(value, bool):
            return risks

        if isinstance(value, list):
            for v in value:
                risks.append(
                    self._record_from_violation(
                        v, policy_name=policy_name, default_severity=Severity.HIGH
                    )
                )
            return risks

        if isinstance(value, dict):
            deny_items = (
                value.get("deny") or value.get("violations") or value.get("risks")
            )
            warn_items = value.get("warn") or value.get("warnings")

            if isinstance(deny_items, list):
                for item in deny_items:
                    risks.append(
                        self._record_from_violation(
                            item,
                            policy_name=policy_name,
                            default_severity=Severity.HIGH,
                        )
                    )
            if isinstance(warn_items, list):
                for item in warn_items:
                    risks.append(
                        self._record_from_violation(
                            item,
                            policy_name=policy_name,
                            default_severity=Severity.MEDIUM,
                        )
                    )

            if risks:
                return risks

            # 辞書が単一違反を表すケース
            risks.append(
                self._record_from_violation(
                    value, policy_name=policy_name, default_severity=Severity.HIGH
                )
            )
            return risks

        # 文字列や数値など
        risks.append(
            self._record_from_violation(
                value, policy_name=policy_name, default_severity=Severity.HIGH
            )
        )
        return risks

    def evaluate(
        self, input_data: Dict[str, Any], policy_name: str
    ) -> List[RiskRecord]:
        """
        指定されたポリシー(Rego)に対して入力データを評価し、リスクレコードのリストを返す。
        現状はプレースホルダーであり、将来的に subprocess 経由等で opa eval を呼び出す想定。
        """
        opa_bin = shutil.which("opa")
        if not opa_bin:
            return []

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", suffix=".json", delete=False
            ) as tmp:
                json.dump(input_data, tmp, ensure_ascii=False)
                tmp_path = tmp.name

            args = [
                opa_bin,
                "eval",
                "-f",
                "json",
                "-d",
                str(self.policy_dir),
                "-i",
                tmp_path,
                f"data.{policy_name}",
            ]

            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if proc.returncode != 0:
                return []

            payload = json.loads(proc.stdout or "{}")
            result = payload.get("result", [])
            risks: List[RiskRecord] = []

            for entry in result:
                for expr in entry.get("expressions", []):
                    value = expr.get("value")
                    risks.extend(self._extract_risks_from_value(value, policy_name))

            return risks
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError):
            return []
        finally:
            try:
                if "tmp_path" in locals():
                    Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass


class G1OpaPolicyRule(Rule):
    @property
    def category(self) -> str:
        return "G-1"

    @property
    def name(self) -> str:
        return "汎用ポリシー評価 (OPA/Rego)"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        policy_dir = repo_path / "policies"

        # ユーザーが独自にポリシーディレクトリを配置している場合のみ動作
        if not policy_dir.exists() or not policy_dir.is_dir():
            return risks

        opa_engine = OPAIntegrationEngine(policy_dir)

        # 例として、ルートディレクトリの package.json を OPA に流し込む
        package_json = repo_path / "package.json"
        if package_json.exists():
            try:
                with open(package_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                risks.extend(opa_engine.evaluate(data, "oss_risk.package_json"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                pass

        return risks
