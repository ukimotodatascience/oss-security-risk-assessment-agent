from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
from pydantic import BaseModel

from oss_risk_agent import __version__

from .models import RiskRecord, Severity


DEFAULT_FAIL_CONDITIONS: Dict[str, int] = {
    "critical": 1,
    "high": 3,
    "total_score": 15,
}

SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}


class GateResult(BaseModel):
    fail: bool
    critical_count: int
    high_count: int
    total_score: int
    fail_conditions: Dict[str, int]
    evaluated_risk_count: int


def _normalize_path(path_str: str) -> str:
    p = Path(path_str)
    return p.as_posix().lstrip("./")


def risk_fingerprint(risk: RiskRecord) -> str:
    payload = {
        "category": risk.category,
        "target_file": _normalize_path(risk.target_file),
        "line_number": risk.line_number,
        "name": risk.name,
        "description": risk.description,
        "evidence": risk.evidence,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_fail_conditions(repo_path: Path, policy_file: str) -> Dict[str, int]:
    policy_path = repo_path / policy_file
    conditions = dict(DEFAULT_FAIL_CONDITIONS)
    if not policy_path.exists():
        return conditions

    data = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    raw = data.get("fail_conditions", {}) or {}

    for key in ["critical", "high", "total_score"]:
        val = raw.get(key)
        if isinstance(val, int) and val >= 0:
            conditions[key] = val

    return conditions


def _fail_conditions_from_profile(fail_on: List[str]) -> Dict[str, int]:
    fail_on_set = {str(s).upper() for s in (fail_on or [])}
    # If a severity is included in fail_on, threshold=1, otherwise large threshold.
    return {
        "critical": 1 if "CRITICAL" in fail_on_set else 10**9,
        "high": 1 if "HIGH" in fail_on_set else 10**9,
        "total_score": 10**9,
    }


def load_fail_conditions_with_profile(
    repo_path: Path, policy_file: str, profile: Optional[str]
) -> Dict[str, int]:
    conditions = load_fail_conditions(repo_path, policy_file)
    if not profile:
        return conditions

    policy_path = repo_path / policy_file
    if not policy_path.exists():
        # Fallback defaults compatible with specification examples
        if profile == "production":
            return _fail_conditions_from_profile(["CRITICAL", "HIGH"])
        if profile == "development":
            return _fail_conditions_from_profile(["CRITICAL"])
        return conditions

    data = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    prof = (data or {}).get(profile)
    if isinstance(prof, dict) and isinstance(prof.get("fail_on"), list):
        return _fail_conditions_from_profile(prof.get("fail_on", []))
    return conditions


def calculate_total_score(risks: List[RiskRecord]) -> int:
    score = 0
    for r in risks:
        score += SEVERITY_WEIGHTS.get(r.severity, 0)
    return score


def evaluate_gate(
    risks: List[RiskRecord], fail_conditions: Dict[str, int]
) -> GateResult:
    critical_count = sum(1 for r in risks if r.severity == Severity.CRITICAL)
    high_count = sum(1 for r in risks if r.severity == Severity.HIGH)
    total_score = calculate_total_score(risks)

    fail = (
        critical_count >= fail_conditions["critical"]
        or high_count >= fail_conditions["high"]
        or total_score >= fail_conditions["total_score"]
    )

    return GateResult(
        fail=fail,
        critical_count=critical_count,
        high_count=high_count,
        total_score=total_score,
        fail_conditions=fail_conditions,
        evaluated_risk_count=len(risks),
    )


def apply_ignore_rules(
    risks: List[RiskRecord],
    repo_path: Path,
    ignore_file: str,
    ignore_expired_check: bool = False,
) -> Tuple[List[RiskRecord], List[dict]]:
    ignore_path = repo_path / ignore_file
    if not ignore_path.exists():
        return risks, []

    rules = []

    if ignore_path.name == ".oss-riskignore":
        # format: B-5:workflow.yml:期限=2026-06-01:理由=検証中
        for raw_line in ignore_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            rule_id = parts[0].strip()
            path = parts[1].strip()
            expiry = None
            reason = ""
            for p in parts[2:]:
                if p.startswith("期限="):
                    expiry = p.replace("期限=", "", 1).strip()
                elif p.startswith("理由="):
                    reason = p.replace("理由=", "", 1).strip()
            rules.append(
                {
                    "rule_id": rule_id,
                    "path": path,
                    "reason": reason,
                    "expiry": expiry,
                }
            )
    else:
        data = yaml.safe_load(ignore_path.read_text(encoding="utf-8")) or {}
        rules = data.get("ignore_rules", []) or []

    remaining: List[RiskRecord] = []
    applied: List[dict] = []

    for risk in risks:
        matched = None
        fp = risk_fingerprint(risk)
        r_path = _normalize_path(risk.target_file)
        for rule in rules:
            if rule.get("rule_id") != risk.category:
                continue
            if _normalize_path(str(rule.get("path", ""))) != r_path:
                continue
            expiry = rule.get("expiry")
            if expiry and not ignore_expired_check:
                try:
                    exp_dt = datetime.fromisoformat(str(expiry))
                    now = (
                        datetime.now(exp_dt.tzinfo) if exp_dt.tzinfo else datetime.now()
                    )
                    if exp_dt < now:
                        continue
                except Exception:
                    # invalid expiry format -> do not ignore
                    continue
            expected_hash = rule.get("hash")
            if expected_hash and expected_hash != fp:
                continue
            matched = rule
            break

        if matched is None:
            remaining.append(risk)
            continue

        applied.append(
            {
                "rule_id": matched.get("rule_id"),
                "path": matched.get("path"),
                "reason": matched.get("reason", ""),
                "hash": matched.get("hash"),
                "risk_fingerprint": fp,
            }
        )

    return remaining, applied


def create_baseline_payload(risks: List[RiskRecord]) -> dict:
    items = []
    for r in risks:
        items.append(
            {
                "fingerprint": risk_fingerprint(r),
                "category": r.category,
                "target_file": _normalize_path(r.target_file),
                "line_number": r.line_number,
                "name": r.name,
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": __version__,
        "risks": items,
    }


def apply_baseline(
    risks: List[RiskRecord], baseline_file: Optional[str], repo_path: Path
) -> Tuple[List[RiskRecord], List[RiskRecord], int]:
    if not baseline_file:
        return risks, risks, 0

    baseline_path = Path(baseline_file)
    if not baseline_path.is_absolute():
        baseline_path = repo_path / baseline_path

    if not baseline_path.exists():
        return risks, risks, 0

    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    known = {
        i.get("fingerprint") for i in data.get("risks", []) if i.get("fingerprint")
    }

    all_output: List[RiskRecord] = []
    gate_targets: List[RiskRecord] = []
    existing_count = 0

    for r in risks:
        fp = risk_fingerprint(r)
        if fp in known:
            existing_count += 1
            dump = getattr(r, "model_dump", r.dict)
            copied = dump()
            copied["severity"] = Severity.INFORMATIONAL
            all_output.append(RiskRecord(**copied))
            continue
        all_output.append(r)
        gate_targets.append(r)

    return all_output, gate_targets, existing_count


def build_audit_log(
    repo_path: Path,
    fail_conditions: Dict[str, int],
    ignore_applied_history: List[dict],
    policy_file: str,
) -> dict:
    repo_hash = "unknown"
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        repo_hash = proc.stdout.strip()
    except Exception:
        repo_hash = "unknown"

    policy_path = repo_path / policy_file
    policy_version = "default-v1"
    if policy_path.exists():
        try:
            data = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
            policy_version = data.get("policy_version", policy_version)
        except Exception:
            pass

    return {
        "scan_datetime": datetime.now(timezone.utc).isoformat(),
        "repository_hash": repo_hash,
        "rule_version": __version__,
        "policy_version": policy_version,
        "fail_conditions": fail_conditions,
        "ignore_applied_history": ignore_applied_history,
    }
