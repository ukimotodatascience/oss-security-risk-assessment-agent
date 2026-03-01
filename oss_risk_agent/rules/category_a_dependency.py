from pathlib import Path
from typing import List
import json
import re

from ..core.models import Rule, RiskRecord, Severity
from ..utils.osv_client import check_vulnerability
from ..utils.parsers import parse_requirements_txt, parse_package_json
from ..utils.epss_client import get_epss_score
from ..utils.kev_client import is_known_exploited
from ..utils.sbom import (
    collect_dependencies,
    generate_cyclonedx_sbom,
    has_unpinned_version,
)


class A1VulnerableDependencyRule(Rule):
    @property
    def category(self) -> str:
        return "A-1"

    @property
    def name(self) -> str:
        return "既知の脆弱性を含む依存ライブラリ"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []

        # Python requirements.txt
        req_file = repo_path / "requirements.txt"
        if req_file.exists():
            from ..utils.epss_client import get_epss_score

            deps = parse_requirements_txt(req_file)
            for pkg_name, version_spec, line_num in deps:
                # 簡易判定：バージョンが固定(==)されているもののみ正確にチェック可能とする
                if "==" in version_spec:
                    ver = version_spec.replace("==", "").strip()
                    vuln_data = check_vulnerability(pkg_name, ver, ecosystem="PyPI")
                    if vuln_data:
                        severity = Severity.MEDIUM

                        vulns = vuln_data.get("vulns", [])
                        vuln_ids = [v.get("id") for v in vulns]

                        max_epss = 0.0
                        max_cvss = 0.0

                        for vuln in vulns:
                            vid = vuln.get("id")

                            # Extract CVSS
                            if "severity" in vuln:
                                for s in vuln["severity"]:
                                    if s.get("type") in ["CVSS_V3", "CVSS_V4"]:
                                        score_str = s.get("score", "")
                                        # Simple heuristic to extract numerical score or assume HIGH if parsing fails
                                        if "baseScore" in score_str:
                                            try:
                                                parts = score_str.split("baseScore:")
                                                cvss_val = float(parts[1][:3])
                                                max_cvss = max(max_cvss, cvss_val)
                                            except:
                                                max_cvss = max(
                                                    max_cvss, 7.0
                                                )  # Fallback to High
                                        else:
                                            # Actually OSV returns vector strings like CVSS:3.1/AV:N...
                                            # Full CVSS parsing is complex, we assign a baseline if CVSS exists
                                            max_cvss = max(max_cvss, 7.0)

                            if vid.startswith("CVE-"):
                                epss = get_epss_score(vid)
                                if epss and epss > max_epss:
                                    max_epss = epss

                        # Composite logic:
                        if max_cvss >= 9.0 or max_epss >= 0.10:
                            severity = Severity.CRITICAL
                        elif max_cvss >= 7.0 or max_epss >= 0.01:
                            severity = Severity.HIGH

                        epss_note = (
                            f" (Max EPSS: {max_epss:.1%} | Max CVSS: {max_cvss})"
                        )
                        desc = f"パッケージ '{pkg_name}' (バージョン {ver}) に既知の脆弱性があります: {', '.join(vuln_ids)}{epss_note}"

                        risks.append(
                            RiskRecord(
                                category=self.category,
                                name=self.name,
                                severity=severity,
                                description=desc,
                                target_file="requirements.txt",
                                line_number=line_num,
                                evidence=f"{pkg_name} {version_spec}",
                                score_metadata={"epss": max_epss, "cvss": max_cvss},
                            )
                        )

        # Python poetry.lock (推移的依存の解決)
        poetry_lock = repo_path / "poetry.lock"
        if poetry_lock.exists():
            from ..utils.parsers import parse_poetry_lock

            resolved_deps_py = parse_poetry_lock(poetry_lock)

            from ..utils.epss_client import get_epss_score

            for pkg_name, ver in resolved_deps_py.items():
                vuln_data = check_vulnerability(pkg_name, ver, ecosystem="PyPI")
                if vuln_data:
                    severity = Severity.HIGH
                    vuln_ids = [v.get("id") for v in vuln_data.get("vulns", [])]

                    max_epss = 0.0
                    for vid in vuln_ids:
                        if vid.startswith("CVE-"):
                            epss = get_epss_score(vid)
                            if epss and epss > max_epss:
                                max_epss = epss

                    epss_note = ""
                    if max_epss >= 0.10:
                        severity = Severity.CRITICAL
                        epss_note = f" (最大EPSS: {max_epss:.1%} - 悪用可能性高)"
                    elif max_epss > 0:
                        epss_note = f" (最大EPSS: {max_epss:.1%})"

                    desc = f"パッケージ '{pkg_name}' (バージョン {ver}) に既知の脆弱性があります: {', '.join(vuln_ids)}{epss_note}"

                    risks.append(
                        RiskRecord(
                            category=self.category,
                            name=self.name,
                            severity=severity,
                            description=desc,
                            target_file="poetry.lock",
                            evidence=f"推移的依存パッケージ: {pkg_name}@{ver}",
                        )
                    )

        # Node.js package-lock.json (推移的依存の解決)
        pkg_lock = repo_path / "package-lock.json"

        if pkg_lock.exists():
            from ..utils.parsers import parse_package_lock_json

            resolved_deps = parse_package_lock_json(pkg_lock)

            from ..utils.epss_client import get_epss_score

            for pkg_name, ver in resolved_deps.items():
                vuln_data = check_vulnerability(pkg_name, ver, ecosystem="npm")
                if vuln_data:
                    severity = Severity.HIGH
                    vuln_ids = [v.get("id") for v in vuln_data.get("vulns", [])]

                    # EPSSスコア評価
                    max_epss = 0.0
                    for vid in vuln_ids:
                        if vid.startswith("CVE-"):
                            epss = get_epss_score(vid)
                            if epss and epss > max_epss:
                                max_epss = epss

                    epss_note = ""
                    if max_epss >= 0.10:
                        severity = Severity.CRITICAL
                        epss_note = f" (最大EPSS: {max_epss:.1%} - 悪用可能性高)"
                    elif max_epss > 0:
                        epss_note = f" (最大EPSS: {max_epss:.1%})"

                    desc = f"パッケージ '{pkg_name}' (バージョン {ver}) に既知の脆弱性があります: {', '.join(vuln_ids)}{epss_note}"

                    risks.append(
                        RiskRecord(
                            category=self.category,
                            name=self.name,
                            severity=severity,
                            description=desc,
                            target_file="package-lock.json",
                            evidence=f"推移的依存パッケージ: {pkg_name}@{ver}",
                        )
                    )

        # Go go.sum (推移的依存の解決)
        go_sum = repo_path / "go.sum"
        go_mod = repo_path / "go.mod"
        go_file = go_sum if go_sum.exists() else go_mod

        if go_file.exists():
            from ..utils.parsers import parse_go_mod

            resolved_deps = parse_go_mod(go_file)

            from ..utils.epss_client import get_epss_score

            for pkg_name, ver in resolved_deps.items():
                vuln_data = check_vulnerability(pkg_name, ver, ecosystem="Go")
                if vuln_data:
                    severity = Severity.HIGH
                    vuln_ids = [v.get("id") for v in vuln_data.get("vulns", [])]

                    max_epss = 0.0
                    for vid in vuln_ids:
                        if vid.startswith("CVE-"):
                            epss = get_epss_score(vid)
                            if epss and epss > max_epss:
                                max_epss = epss

                    epss_note = ""
                    if max_epss >= 0.10:
                        severity = Severity.CRITICAL
                        epss_note = f" (最大EPSS: {max_epss:.1%} - 悪用可能性高)"
                    elif max_epss > 0:
                        epss_note = f" (最大EPSS: {max_epss:.1%})"

                    desc = f"パッケージ '{pkg_name}' (バージョン {ver}) に既知の脆弱性があります: {', '.join(vuln_ids)}{epss_note}"

                    risks.append(
                        RiskRecord(
                            category=self.category,
                            name=self.name,
                            severity=severity,
                            description=desc,
                            target_file=go_file.name,
                            evidence=f"推移的依存モジュール: {pkg_name}@{ver}",
                        )
                    )

        # Rust Cargo.lock (推移的依存の解決)
        cargo_lock = repo_path / "Cargo.lock"

        if cargo_lock.exists():
            from ..utils.parsers import parse_cargo_lock

            resolved_deps = parse_cargo_lock(cargo_lock)

            from ..utils.epss_client import get_epss_score

            for pkg_name, ver in resolved_deps.items():
                vuln_data = check_vulnerability(pkg_name, ver, ecosystem="crates.io")
                if vuln_data:
                    severity = Severity.HIGH
                    vuln_ids = [v.get("id") for v in vuln_data.get("vulns", [])]

                    max_epss = 0.0
                    for vid in vuln_ids:
                        if vid.startswith("CVE-"):
                            epss = get_epss_score(vid)
                            if epss and epss > max_epss:
                                max_epss = epss

                    epss_note = ""
                    if max_epss >= 0.10:
                        severity = Severity.CRITICAL
                        epss_note = f" (最大EPSS: {max_epss:.1%} - 悪用可能性高)"
                    elif max_epss > 0:
                        epss_note = f" (最大EPSS: {max_epss:.1%})"

                    desc = f"パッケージ '{pkg_name}' (バージョン {ver}) に既知の脆弱性があります: {', '.join(vuln_ids)}{epss_note}"

                    risks.append(
                        RiskRecord(
                            category=self.category,
                            name=self.name,
                            severity=severity,
                            description=desc,
                            target_file="Cargo.lock",
                            evidence=f"推移的依存クレート: {pkg_name}@{ver}",
                        )
                    )

        return risks


class A2UnpinnedDependencyRule(Rule):
    @property
    def category(self) -> str:
        return "A-2"

    @property
    def name(self) -> str:
        return "依存バージョン未固定"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []

        # Python
        req_file = repo_path / "requirements.txt"
        poetry_lock = repo_path / "poetry.lock"
        pipfile_lock = repo_path / "Pipfile.lock"

        has_py_lock = poetry_lock.exists() or pipfile_lock.exists()

        if req_file.exists():
            deps = parse_requirements_txt(req_file)
            # Python versions are often unpinned if they use >=, >, <, <=, ~=, ~ or no version at all.
            # Only exact matching == is considered securely pinned in absence of lockfiles.
            unpinned = [d for d in deps if "==" not in d[1]]

            if unpinned and not has_py_lock:
                for pkg_name, ver_spec, line_num in unpinned:
                    risks.append(
                        RiskRecord(
                            category=self.category,
                            name=self.name,
                            severity=Severity.MEDIUM,
                            description=f"要件ファイルで '{pkg_name}' のバージョンが固定されておらず、ロックファイルも存在しません。",
                            target_file="requirements.txt",
                            line_number=line_num,
                            evidence=f"{pkg_name} {ver_spec}",
                        )
                    )

        # Node.js
        pkg_json = repo_path / "package.json"
        pkg_lock = repo_path / "package-lock.json"
        yarn_lock = repo_path / "yarn.lock"
        pnpm_lock = repo_path / "pnpm-lock.yaml"

        has_js_lock = pkg_lock.exists() or yarn_lock.exists() or pnpm_lock.exists()

        # Go
        go_mod = repo_path / "go.mod"
        go_sum = repo_path / "go.sum"

        if go_mod.exists() and not go_sum.exists():
            risks.append(
                RiskRecord(
                    category=self.category,
                    name=self.name,
                    severity=Severity.MEDIUM,
                    description=f"go.modが存在しますが、ロックファイル(go.sum)が存在しません。",
                    target_file="go.mod",
                    evidence="go.sumが存在しない",
                )
            )

        # Rust
        cargo_toml = repo_path / "Cargo.toml"
        cargo_lock = repo_path / "Cargo.lock"

        if cargo_toml.exists() and not cargo_lock.exists():
            risks.append(
                RiskRecord(
                    category=self.category,
                    name=self.name,
                    severity=Severity.MEDIUM,
                    description=f"Cargo.tomlが存在しますが、ロックファイル(Cargo.lock)が存在しません。",
                    target_file="Cargo.toml",
                    evidence="Cargo.lockが存在しない",
                )
            )

        if pkg_json.exists():
            deps, dev_deps = parse_package_json(pkg_json)
            all_deps = {**deps, **dev_deps}

            unpinned_js = []
            for pkg, ver in all_deps.items():
                # npmのバージョン指定で固定されていない（^, ~, *, >, <, =x.x などを含む）か確認
                # Semantic versioning checks
                # Only absolute strict version like "1.2.3" is pinned.
                # The rule checks for any dynamic modifiers.
                if any(char in ver for char in ["^", "~", "*", ">", "<", "x", "X"]):
                    unpinned_js.append((pkg, ver))
                elif len(ver.split(".")) < 3 and ver != "":
                    # "1.2" implies "1.2.x" in many contexts
                    unpinned_js.append((pkg, ver))

            if unpinned_js and not has_js_lock:
                risks.append(
                    RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=Severity.MEDIUM,
                        description=f"package.json内で複数の依存バージョンが固定されておらず、ロックファイル({pkg_lock.name}など)が存在しません。",
                        target_file="package.json",
                        evidence=f"未固定パッケージの例: {unpinned_js[0][0]} ({unpinned_js[0][1]})",
                    )
                )

        return risks


class A3SbomGenerationRule(Rule):
    @property
    def category(self) -> str:
        return "A-3"

    @property
    def name(self) -> str:
        return "SBOM生成および検証"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks: List[RiskRecord] = []

        sbom_candidates = [
            repo_path / "sbom.cdx.json",
            repo_path / "sbom.json",
            repo_path / "bom.json",
        ]
        existing_sbom = next((p for p in sbom_candidates if p.exists()), None)

        deps = collect_dependencies(repo_path)
        evidence = (
            ", ".join(
                [f"{eco}:{name}@{ver or 'N/A'}" for eco, name, ver, _ in deps[:20]]
            )
            or "依存関係なし"
        )

        if existing_sbom is None:
            risks.append(
                RiskRecord(
                    category=self.category,
                    name=self.name,
                    severity=Severity.MEDIUM,
                    description="SBOMが未生成です。CycloneDX形式で生成してください。",
                    target_file="dependencies",
                    evidence=evidence,
                )
            )
        else:
            # 既存SBOMを検証
            try:
                with open(existing_sbom, "r", encoding="utf-8") as f:
                    sbom_obj = json.load(f)
                if sbom_obj.get("bomFormat") != "CycloneDX":
                    risks.append(
                        RiskRecord(
                            category=self.category,
                            name=self.name,
                            severity=Severity.MEDIUM,
                            description="SBOMがCycloneDX形式ではありません。",
                            target_file=str(existing_sbom.relative_to(repo_path)),
                            evidence=f"bomFormat={sbom_obj.get('bomFormat')}",
                        )
                    )
            except Exception:
                risks.append(
                    RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=Severity.MEDIUM,
                        description="SBOMファイルを読み込めませんでした。",
                        target_file=str(existing_sbom.relative_to(repo_path)),
                        evidence="JSON parse error",
                    )
                )

        unpinned = [d for d in deps if has_unpinned_version(d[2])]
        if unpinned:
            sample = unpinned[0]
            risks.append(
                RiskRecord(
                    category=self.category,
                    name=self.name,
                    severity=Severity.HIGH,
                    description="SBOM対象依存にバージョン未固定の依存関係があります。",
                    target_file="dependencies",
                    evidence=f"例: {sample[1]} {sample[2]}",
                )
            )

        if existing_sbom is not None:
            try:
                with open(existing_sbom, "r", encoding="utf-8") as f:
                    sbom_obj = json.load(f)
                has_signature = bool(sbom_obj.get("signature"))
                if not has_signature:
                    risks.append(
                        RiskRecord(
                            category=self.category,
                            name=self.name,
                            severity=Severity.LOW,
                            description="署名なしSBOMです。",
                            target_file=str(existing_sbom.relative_to(repo_path)),
                            evidence="signature field not found",
                        )
                    )
            except Exception:
                pass

        return risks


class A4EffectiveVulnerabilityPriorityRule(Rule):
    @property
    def category(self) -> str:
        return "A-4"

    @property
    def name(self) -> str:
        return "実効脆弱性優先度評価"

    def _extract_cvss_base(self, vuln: dict) -> float:
        # OSV severity string is often vector-like; for enterprise rule we default to
        # a conservative baseline if an explicit score cannot be parsed.
        severities = vuln.get("severity", []) or []
        for s in severities:
            raw = s.get("score", "")
            m = re.search(r"([0-9]+\.[0-9]+)", str(raw))
            if m:
                try:
                    return float(m.group(1))
                except ValueError:
                    pass
        return 7.0 if severities else 0.0

    def _severity_from_inputs(self, cvss: float, epss: float, kev: bool) -> Severity:
        if kev:
            return Severity.CRITICAL
        if cvss >= 8.0 and epss >= 0.2:
            return Severity.HIGH
        if cvss >= 7.0:
            return Severity.MEDIUM
        return Severity.LOW

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks: List[RiskRecord] = []
        deps = collect_dependencies(repo_path)

        for ecosystem, name, ver_spec, _ in deps:
            # versionが定まらないとOSV照会結果の品質が落ちるためスキップ
            if has_unpinned_version(ver_spec):
                continue

            version = ver_spec.replace("==", "").strip()
            vuln_data = check_vulnerability(name, version, ecosystem=ecosystem)
            if not vuln_data:
                continue

            for vuln in vuln_data.get("vulns", []):
                vuln_id = vuln.get("id", "UNKNOWN")
                cvss = self._extract_cvss_base(vuln)
                epss = get_epss_score(vuln_id) if vuln_id.startswith("CVE-") else 0.0
                epss = float(epss or 0.0)
                kev_flag = is_known_exploited(vuln_id)
                effective_score = (
                    (cvss * 0.6) + (epss * 10.0 * 0.3) + (2 if kev_flag else 0)
                )
                severity = self._severity_from_inputs(cvss, epss, kev_flag)

                risks.append(
                    RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=severity,
                        description=f"{name}@{version} に脆弱性 {vuln_id} が存在します。実効優先度を評価しました。",
                        target_file="dependencies",
                        evidence=f"{ecosystem}:{name}@{version}",
                        score_metadata={
                            "cvss": round(cvss, 2),
                            "epss": round(epss, 4),
                            "kev": kev_flag,
                            "effective_score": round(effective_score, 2),
                            "vulnerability_id": vuln_id,
                        },
                    )
                )

        return risks
