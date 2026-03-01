import json
from datetime import datetime
from typing import List

from pydantic import BaseModel

from .models import RiskRecord, Severity

def convert_to_sarif(risks: List[RiskRecord]) -> str:
    """
    リスクレコードのリストをSARIF v2.1.0フォーマットのJSON文字列に変換する
    """
    # 深刻度をSARIFのレベルにマッピング
    level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note"
    }

    rules = {}
    results = []

    for risk in risks:
        # ルール定義の構築
        rule_id = f"OSS-RISK-{risk.category}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": risk.name,
                "shortDescription": {"text": risk.name},
                "defaultConfiguration": {
                    "level": level_map.get(risk.severity, "warning")
                },
                "properties": {
                    "category": risk.category,
                    "severity": risk.severity.value
                }
            }
        
        # リザルト（検出項目）の構築
        result = {
            "ruleId": rule_id,
            "level": level_map.get(risk.severity, "warning"),
            "message": {
                "text": risk.description
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": risk.target_file,
                        },
                        "region": {
                            "startLine": risk.line_number if risk.line_number else 1,
                            "snippet": {
                                "text": risk.evidence
                            }
                        }
                    }
                }
            ]
        }
        results.append(result)

    sarif_log = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OSS Risk Assessment Agent",
                        "informationUri": "https://github.com/ukimotodatascience/oss-security-risk-assessment-agent",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }
        ]
    }

    return json.dumps(sarif_log, indent=2, ensure_ascii=False)
