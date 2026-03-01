from pathlib import Path
from typing import List
import json

from ..core.models import Rule, RiskRecord, Severity
from ..utils.osv_client import check_vulnerability
from ..utils.parsers import parse_requirements_txt, parse_package_json

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
                                                 max_cvss = max(max_cvss, 7.0) # Fallback to High
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

                        epss_note = f" (Max EPSS: {max_epss:.1%} | Max CVSS: {max_cvss})"
                        desc = f"パッケージ '{pkg_name}' (バージョン {ver}) に既知の脆弱性があります: {', '.join(vuln_ids)}{epss_note}"
                        
                        risks.append(RiskRecord(
                            category=self.category,
                            name=self.name,
                            severity=severity,
                            description=desc,
                            target_file="requirements.txt",
                            line_number=line_num,
                            evidence=f"{pkg_name} {version_spec}",
                            score_metadata={"epss": max_epss, "cvss": max_cvss}
                        ))
        
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
                    
                    risks.append(RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=severity,
                        description=desc,
                        target_file="poetry.lock",
                        evidence=f"推移的依存パッケージ: {pkg_name}@{ver}"
                    ))
        
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
                    
                    risks.append(RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=severity,
                        description=desc,
                        target_file="package-lock.json",
                        evidence=f"推移的依存パッケージ: {pkg_name}@{ver}"
                    ))
        
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
                    
                    risks.append(RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=severity,
                        description=desc,
                        target_file=go_file.name,
                        evidence=f"推移的依存モジュール: {pkg_name}@{ver}"
                    ))

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
                    
                    risks.append(RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=severity,
                        description=desc,
                        target_file="Cargo.lock",
                        evidence=f"推移的依存クレート: {pkg_name}@{ver}"
                    ))

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
                    risks.append(RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=Severity.MEDIUM,
                        description=f"要件ファイルで '{pkg_name}' のバージョンが固定されておらず、ロックファイルも存在しません。",
                        target_file="requirements.txt",
                        line_number=line_num,
                        evidence=f"{pkg_name} {ver_spec}"
                    ))
        
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
             risks.append(RiskRecord(
                 category=self.category,
                 name=self.name,
                 severity=Severity.MEDIUM,
                 description=f"go.modが存在しますが、ロックファイル(go.sum)が存在しません。",
                 target_file="go.mod",
                 evidence="go.sumが存在しない"
             ))

        # Rust
        cargo_toml = repo_path / "Cargo.toml"
        cargo_lock = repo_path / "Cargo.lock"
        
        if cargo_toml.exists() and not cargo_lock.exists():
             risks.append(RiskRecord(
                 category=self.category,
                 name=self.name,
                 severity=Severity.MEDIUM,
                 description=f"Cargo.tomlが存在しますが、ロックファイル(Cargo.lock)が存在しません。",
                 target_file="Cargo.toml",
                 evidence="Cargo.lockが存在しない"
             ))
        
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
                elif len(ver.split('.')) < 3 and ver != "":
                    # "1.2" implies "1.2.x" in many contexts
                    unpinned_js.append((pkg, ver))
                    
            if unpinned_js and not has_js_lock:
                risks.append(RiskRecord(
                    category=self.category,
                    name=self.name,
                    severity=Severity.MEDIUM,
                    description=f"package.json内で複数の依存バージョンが固定されておらず、ロックファイル({pkg_lock.name}など)が存在しません。",
                    target_file="package.json",
                    evidence=f"未固定パッケージの例: {unpinned_js[0][0]} ({unpinned_js[0][1]})"
                ))
                
        return risks
