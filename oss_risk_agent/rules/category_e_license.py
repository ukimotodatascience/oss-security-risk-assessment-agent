from pathlib import Path
from typing import List
import re

from ..core.models import Rule, RiskRecord, Severity

class E1GplLicenseRule(Rule):
    @property
    def category(self) -> str:
        return "E-1"

    @property
    def name(self) -> str:
        return "GPL系ライセンス"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        # 大文字小文字を無視してLICENSEファイルを探索
        license_files = list(repo_path.glob("LICENSE*")) + list(repo_path.glob("license*"))
        
        gpl_patterns = [
            r"\bGPL-?[23]?\.0?\b",
            r"\bGNU General Public License\b",
            r"\bAGPL\b",
            r"\bAffero General Public License\b"
        ]
        
        for lf in license_files:
            try:
                with open(lf, "r", encoding="utf-8") as f:
                    content = f.read()
                    
                    found = False
                    for p in gpl_patterns:
                        if re.search(p, content, re.IGNORECASE):
                            found = True
                            break
                            
                    if found:
                        risks.append(RiskRecord(
                            category=self.category,
                            name=self.name,
                            severity=Severity.MEDIUM,
                            description=f"商用利用時にソースコード公開義務が発生する可能性がある強いコピーレフトライセンスが '{lf.name}' で検出されました。",
                            target_file=str(lf.relative_to(repo_path)),
                            evidence="GPL系キーワードの検出"
                        ))
            except Exception:
                pass
                
        return risks

class E2MissingLicenseRule(Rule):
    @property
    def category(self) -> str:
        return "E-2"

    @property
    def name(self) -> str:
        return "ライセンス未定義"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        license_files = list(repo_path.glob("LICENSE*")) + list(repo_path.glob("license*"))
        
        if not license_files:
            risks.append(RiskRecord(
                category=self.category,
                name=self.name,
                severity=Severity.HIGH,
                description="LICENSEファイルが存在しません。法的利用条件が不明であり、利用自体がリスクとなります。",
                target_file="[Repository Root]",
                evidence="LICENSEファイルの不在"
            ))
            
        return risks
