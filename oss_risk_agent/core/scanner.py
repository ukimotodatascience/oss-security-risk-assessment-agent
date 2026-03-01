import pkgutil
import importlib
import inspect
from pathlib import Path
from typing import List
from rich.console import Console

from .models import Rule, RiskRecord, ScanWarning

console = Console()


class Scanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.rules: List[Rule] = []
        self.warnings: List[ScanWarning] = []
        self._load_rules()

    def _load_rules(self):
        """oss_risk_agent.rulesパッケージからRuleを継承するクラスを動的にロードする"""
        import oss_risk_agent.rules as rules_mod

        # rulesディレクトリ内の全モジュールを探索
        for _, name, _ in pkgutil.iter_modules(rules_mod.__path__):
            try:
                mod = importlib.import_module(f"oss_risk_agent.rules.{name}")
            except Exception as e:
                self.warnings.append(
                    ScanWarning(
                        rule_category="N/A",
                        rule_name=f"module:{name}",
                        message=f"ルールモジュールの読み込みに失敗しました: {e}",
                    )
                )
                continue

            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (
                    inspect.isclass(attr)
                    and issubclass(attr, Rule)
                    and attr is not Rule
                ):
                    # 抽象クラスでなければインスタンス化して登録
                    if not inspect.isabstract(attr):
                        try:
                            self.rules.append(attr())
                        except Exception as e:
                            self.warnings.append(
                                ScanWarning(
                                    rule_category="N/A",
                                    rule_name=getattr(attr, "__name__", "unknown"),
                                    message=f"ルールの初期化に失敗しました: {e}",
                                )
                            )

        # core.opa_integration から G1OpaPolicyRule を読み込む
        try:
            from .opa_integration import G1OpaPolicyRule

            self.rules.append(G1OpaPolicyRule())
        except Exception as e:
            self.warnings.append(
                ScanWarning(
                    rule_category="G-1",
                    rule_name="汎用ポリシー評価 (OPA/Rego)",
                    message=f"OPAルールの読み込みに失敗しました: {e}",
                )
            )

        # ルールをカテゴリ順にソート (A-1, B-1など)
        self.rules.sort(key=lambda r: r.category)

    def scan(self) -> List[RiskRecord]:
        """登録された全てのルールを実行してリスクのリストを返す"""
        all_risks = []
        for rule in self.rules:
            # console.print(f"[dim]Running {rule.category} {rule.name}...[/dim]")
            try:
                risks = rule.analyze(self.repo_path)
                all_risks.extend(risks)
            except Exception as e:
                warning = ScanWarning(
                    rule_category=rule.category,
                    rule_name=rule.name,
                    message=f"ルール実行に失敗しました: {e}",
                )
                self.warnings.append(warning)
                console.print(
                    f"[yellow]Warning: {rule.category} ({rule.name}) failed: {e}[/yellow]"
                )
        return all_risks
