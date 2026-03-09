"""Built-in rule skeleton implementations.

Each rule currently provides framework-only behavior and returns no findings.
Detailed detection logic will be implemented in later iterations.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from pathlib import Path
from typing import Mapping, cast

from oss_risk_agent.integrations.advisory_client import AdvisoryClient
from oss_risk_agent.models.risk import Evidence, RiskRecord, Severity

from .base import Rule


class _SkeletonRule(Rule):
    """Common no-op implementation for rule scaffolding."""

    def evaluate(self, target: Path, mode: str) -> list[RiskRecord]:
        _ = (target, mode)
        return []


class A0_SbomFullAnalysisRule(_SkeletonRule):
    """A-0: SBOM full analysis."""

    def __init__(self) -> None:
        super().__init__(rule_id="A-0", category="A", title="SBOM full analysis")

    def evaluate(self, target: Path, mode: str) -> list[RiskRecord]:
        # ============================================================
        # 1) 解析用の作業領域を初期化する
        #    - direct_deps: 直接依存の一意集合
        #    - transitive_deps: 推移依存の一意集合
        #    - evidences: 検出根拠（読んだファイル、生成したSBOMなど）
        #    - components: SBOM components 用の正規化済みコンポーネント
        # ============================================================
        direct_deps: set[str] = set()
        transitive_deps: set[str] = set()
        evidences: list[Evidence] = []
        components: dict[tuple[str, str], dict[str, str | None]] = {}

        # ============================================================
        # 2) Python の直接依存を収集する
        # ============================================================

        # 2-1) requirements.txt を読む
        #      行ベースで依存名・バージョン候補を抽出する
        req = target / "requirements.txt"
        if req.exists() and req.is_file():
            req_components = self._parse_requirements(req)
            if req_components:
                self._merge_components(components, req_components)
                direct_deps.update(name for name, _, _ in req_components)
                evidences.append(Evidence(file=str(req), source="requirements.txt"))

        # 2-2) pyproject.toml を読む
        #      PEP 621 (project.dependencies) と Poetry dependencies を扱う
        pyproject = target / "pyproject.toml"
        if pyproject.exists() and pyproject.is_file():
            pyproject_components = self._parse_pyproject_dependencies(pyproject)
            if pyproject_components:
                self._merge_components(components, pyproject_components)
                direct_deps.update(name for name, _, _ in pyproject_components)
                evidences.append(Evidence(file=str(pyproject), source="pyproject.toml"))

        # ============================================================
        # 3) Node の直接依存を収集する
        # ============================================================

        # 3-1) package.json の dependency 系セクションを読む
        #      dependencies / devDependencies / optional / peer を対象とする
        package_json = target / "package.json"
        if package_json.exists() and package_json.is_file():
            node_direct = self._parse_package_json_direct_dependencies(package_json)
            if node_direct:
                self._merge_components(components, node_direct)
                direct_deps.update(name for name, _, _ in node_direct)
                evidences.append(
                    Evidence(file=str(package_json), source="package.json")
                )

        # ============================================================
        # 4) ロックファイル由来の推移依存を収集する
        # ============================================================

        # 4-1) package-lock.json から推移依存を抽出する
        #      lockfile の packages/dependencies を両方見る
        package_lock = target / "package-lock.json"
        if package_lock.exists() and package_lock.is_file():
            node_transitive = self._parse_package_lock_dependencies(package_lock)
            if node_transitive:
                self._merge_components(components, node_transitive)
                transitive_deps.update(name for name, _, _ in node_transitive)
                evidences.append(
                    Evidence(file=str(package_lock), source="package-lock.json")
                )

        # 4-2) poetry.lock から推移依存を抽出する
        #      [[package]] ブロックの name/version を読む
        poetry_lock = target / "poetry.lock"
        if poetry_lock.exists() and poetry_lock.is_file():
            poetry_transitive = self._parse_poetry_lock_dependencies(poetry_lock)
            if poetry_transitive:
                self._merge_components(components, poetry_transitive)
                transitive_deps.update(name for name, _, _ in poetry_transitive)
                evidences.append(Evidence(file=str(poetry_lock), source="poetry.lock"))

        # ============================================================
        # 5) 依存情報が1件でもあれば CycloneDX SBOM を生成する
        #    失敗してもスキャンは継続し、context にエラー内容を残す
        # ============================================================
        sbom_path: str | None = None
        sbom_generated = False
        sbom_error: str | None = None
        if direct_deps or transitive_deps:
            try:
                sbom_file = self._write_cyclonedx_sbom(
                    target=target,
                    components=list(components.values()),
                )
                sbom_path = str(sbom_file)
                sbom_generated = True
                evidences.append(Evidence(file=str(sbom_file), source="cyclonedx"))
            except OSError as exc:
                sbom_error = str(exc)

        # ============================================================
        # 6) 後段の出力・監査向けメタ情報を組み立てる
        #    - context: ルール結果の補足情報
        #    - coverage: 解析カバレッジの簡易指標
        # ============================================================
        context = {
            "direct_dependencies": len(direct_deps),
            "transitive_dependencies": len(transitive_deps),
            "sbom_generated": sbom_generated,
            "sbom_path": sbom_path,
            "sbom_format": "cyclonedx-json" if sbom_generated else None,
            "sbom_error": sbom_error,
        }

        coverage = {
            "mode": mode,
            "manifest_found": bool(direct_deps),
            "lockfile_found": bool(transitive_deps),
            "direct_dependency_count": len(direct_deps),
            "transitive_dependency_count": len(transitive_deps),
            "sbom_generated": sbom_generated,
        }

        # ============================================================
        # 7) 判定結果を返す
        #    7-1) 依存情報ゼロ: LOW（SBOM解析の前提不足）
        # ============================================================
        if not direct_deps and not transitive_deps:
            return [
                RiskRecord(
                    category=self.category,
                    rule_id=self.rule_id,
                    severity=Severity.LOW,
                    confidence=0.95,
                    evidence=[
                        Evidence(
                            source="dependency-manifest-discovery",
                            snippet="No supported dependency manifest found",
                        )
                    ],
                    remediation=(
                        "requirements.txt / pyproject.toml / package.json とロックファイルを"
                        "配置し、SBOM解析可能な状態にしてください。"
                    ),
                    context=context,
                    coverage=coverage,
                )
            ]

        # 7-2) 直接依存のみ: MEDIUM（ロック不足で完全性不足）
        if direct_deps and not transitive_deps:
            return [
                RiskRecord(
                    category=self.category,
                    rule_id=self.rule_id,
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    evidence=evidences
                    or [
                        Evidence(
                            source="dependency-manifest-discovery",
                            snippet="Direct dependencies found but no lockfile",
                        )
                    ],
                    remediation=(
                        "ロックファイル（poetry.lock / package-lock.json など）を"
                        "コミットし、推移依存まで列挙できるようにしてください。"
                    ),
                    context=context,
                    coverage=coverage,
                )
            ]

        # 7-3) 直接 + 推移依存が取れている: INFO（MITIGATED）
        return [
            RiskRecord(
                category=self.category,
                rule_id=self.rule_id,
                severity=Severity.INFO,
                confidence=0.95,
                evidence=evidences,
                remediation="SBOM解析は完了しています。依存更新時も継続的に確認してください。",
                context=context,
                coverage=coverage,
                status="MITIGATED",
            )
        ]

    @staticmethod
    def _merge_components(
        base: dict[tuple[str, str], dict[str, str | None]],
        values: list[tuple[str, str, str | None]],
    ) -> None:
        # 同一コンポーネント（ecosystem + name）の重複を吸収し、
        # version が未設定なら後続値で補完する。
        for name, ecosystem, version in values:
            key = (ecosystem, name)
            current = base.get(key)
            if current is None:
                base[key] = {
                    "name": name,
                    "ecosystem": ecosystem,
                    "version": version,
                }
                continue

            if not current.get("version") and version:
                current["version"] = version

    @staticmethod
    def _parse_requirements(path: Path) -> list[tuple[str, str, str | None]]:
        # requirements.txt を「1行=1依存」前提で簡易パースする。
        # 厳密な仕様網羅より、壊れないことと最低限の抽出を優先する。
        items: list[tuple[str, str, str | None]] = []
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                continue

            match = re.match(
                r"^([A-Za-z0-9_.\-]+)\s*(?:==|~=|>=|<=|>|<|!=)?\s*([A-Za-z0-9_.\-]+)?",
                line,
            )
            if not match:
                continue

            name = match.group(1).lower()
            version = match.group(2)
            items.append((name, "pypi", version))
        return items

    @staticmethod
    def _parse_pyproject_dependencies(path: Path) -> list[tuple[str, str, str | None]]:
        # pyproject.toml から依存を抽出する。
        # - project.dependencies
        # - tool.poetry.dependencies（python は除外）
        items: list[tuple[str, str, str | None]] = []
        try:
            import tomllib
        except ModuleNotFoundError:
            return items

        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, tomllib.TOMLDecodeError):
            return items

        project = data.get("project", {})
        dependencies = project.get("dependencies", [])
        if isinstance(dependencies, list):
            for dep in dependencies:
                if not isinstance(dep, str):
                    continue
                dep = dep.strip()
                if not dep:
                    continue
                match = re.match(
                    r"^([A-Za-z0-9_.\-]+)\s*(?:==|~=|>=|<=|>|<|!=)?\s*([A-Za-z0-9_.\-]+)?",
                    dep,
                )
                if match:
                    items.append((match.group(1).lower(), "pypi", match.group(2)))

        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        if isinstance(poetry_deps, dict):
            for key, value in poetry_deps.items():
                dep_name = str(key).lower()
                if dep_name == "python":
                    continue

                version: str | None = None
                if isinstance(value, str):
                    version = value.strip() or None
                elif isinstance(value, dict):
                    raw = value.get("version")
                    if isinstance(raw, str):
                        version = raw.strip() or None

                items.append((dep_name, "pypi", version))

        return items

    @staticmethod
    def _parse_package_json_direct_dependencies(
        path: Path,
    ) -> list[tuple[str, str, str | None]]:
        # package.json の依存セクションを横断し、
        # npm コンポーネントとして統一表現へ変換する。
        items: list[tuple[str, str, str | None]] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            return items

        for key in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            section = data.get(key, {})
            if isinstance(section, dict):
                for dep, raw_version in section.items():
                    dep_name = str(dep).lower()
                    version = (
                        str(raw_version).strip() if raw_version is not None else None
                    )
                    items.append((dep_name, "npm", version or None))
        return items

    @staticmethod
    def _parse_package_lock_dependencies(
        path: Path,
    ) -> list[tuple[str, str, str | None]]:
        # package-lock.json から推移依存を抽出する。
        # lockfileVersion 差異に備えて packages/dependencies の双方を見る。
        items: list[tuple[str, str, str | None]] = []
        seen: set[str] = set()
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            return items

        packages = data.get("packages")
        if isinstance(packages, dict):
            for pkg_path, info in packages.items():
                if pkg_path in ("", "."):
                    continue

                if "node_modules/" in pkg_path:
                    name = pkg_path.rsplit("node_modules/", 1)[-1].lower()
                else:
                    continue

                version: str | None = None
                if isinstance(info, dict):
                    raw_version = info.get("version")
                    if isinstance(raw_version, str):
                        version = raw_version.strip() or None

                if name not in seen:
                    items.append((name, "npm", version))
                    seen.add(name)

        deps = data.get("dependencies")
        if isinstance(deps, dict):
            for name, info in deps.items():
                dep_name = str(name).lower()
                version: str | None = None
                if isinstance(info, dict):
                    raw_version = info.get("version")
                    if isinstance(raw_version, str):
                        version = raw_version.strip() or None
                if dep_name not in seen:
                    items.append((dep_name, "npm", version))
                    seen.add(dep_name)

        return items

    @staticmethod
    def _parse_poetry_lock_dependencies(
        path: Path,
    ) -> list[tuple[str, str, str | None]]:
        # poetry.lock をテキストとして走査し、
        # [[package]] 単位で name/version を抜き出す。
        items: list[tuple[str, str, str | None]] = []
        current_name: str | None = None
        current_version: str | None = None
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return items

        for line in text.splitlines():
            row = line.strip()
            if row == "[[package]]":
                if current_name:
                    items.append((current_name, "pypi", current_version))
                current_name = None
                current_version = None
                continue

            if row.startswith("name = "):
                current_name = row.split("=", 1)[1].strip().strip('"').lower()
            elif row.startswith("version = "):
                current_version = row.split("=", 1)[1].strip().strip('"')

        if current_name:
            items.append((current_name, "pypi", current_version))

        return items

    @staticmethod
    def _write_cyclonedx_sbom(
        target: Path,
        components: list[dict[str, str | None]],
    ) -> Path:
        # CycloneDX JSON の最小構成を組み立てる。
        # 生成先は対象リポジトリ配下の sbom.cyclonedx.json とする。
        metadata_component = {
            "type": "application",
            "name": target.name,
            "bom-ref": f"app:{target.name}",
        }
        bom_components: list[dict[str, str]] = []

        for component in sorted(
            components,
            key=lambda c: (
                str(c.get("ecosystem") or ""),
                str(c.get("name") or ""),
            ),
        ):
            name = str(component.get("name") or "").strip()
            ecosystem = str(component.get("ecosystem") or "").strip()
            version = str(component.get("version") or "").strip() or None
            if not name or not ecosystem:
                continue

            purl_type = "pypi" if ecosystem == "pypi" else "npm"
            purl = f"pkg:{purl_type}/{name}"
            if version:
                purl = f"{purl}@{version}"

            item = {
                "type": "library",
                "name": name,
                "bom-ref": purl,
                "purl": purl,
            }
            if version:
                item["version"] = version
            bom_components.append(item)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": metadata_component,
                "tools": [
                    {"vendor": "oss-risk-agent", "name": "A0_SbomFullAnalysisRule"}
                ],
            },
            "components": bom_components,
        }

        output = target / "sbom.cyclonedx.json"
        output.write_text(
            json.dumps(sbom, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return output


class A1_KnownVulnerabilitiesRule(_SkeletonRule):
    """A-1: Known vulnerabilities in dependencies."""

    def __init__(self, advisory_client: AdvisoryClient | None = None) -> None:
        super().__init__(rule_id="A-1", category="A", title="Known vulnerabilities")
        self._advisory_client = advisory_client or AdvisoryClient()

    def evaluate(self, target: Path, mode: str) -> list[RiskRecord]:
        _ = mode
        dependencies = self._collect_dependencies_with_sources(target)

        findings: list[RiskRecord] = []
        scanned_dependencies = 0
        unpinned_dependencies = 0

        for (ecosystem, name), info in dependencies.items():
            version = info.get("version")
            files_raw = info.get("files")
            files = sorted(files_raw) if isinstance(files_raw, set) else []
            if not isinstance(version, str) or not version.strip():
                unpinned_dependencies += 1
                continue

            version = version.strip()
            scanned_dependencies += 1
            signals = self._advisory_client.lookup(
                package_name=name,
                version=version,
                ecosystem=ecosystem,
            )
            for signal in signals:
                severity = self._severity_from_signal(
                    cvss=signal.cvss, kev_flag=signal.kev_flag
                )
                evidence = [
                    Evidence(
                        file=files[0] if files else None,
                        source="advisory",
                        snippet=f"{name}@{version} affected by {signal.cve_id}",
                    )
                ]

                findings.append(
                    RiskRecord(
                        category=self.category,
                        rule_id=self.rule_id,
                        severity=severity,
                        confidence=0.9,
                        evidence=evidence,
                        remediation=(
                            f"{name} の安全なバージョンへ更新してください。"
                            "ロックファイルも合わせて更新し再スキャンしてください。"
                        ),
                        cvss=signal.cvss,
                        epss=signal.epss_percentile,
                        kev_flag=signal.kev_flag,
                        exploit_available=signal.exploit_available,
                        context={
                            "package_name": name,
                            "ecosystem": ecosystem,
                            "version": version,
                            "vulnerability_id": signal.cve_id,
                            "sources": files,
                        },
                    )
                )

        if findings:
            return findings

        return [
            RiskRecord(
                category=self.category,
                rule_id=self.rule_id,
                severity=Severity.INFO,
                confidence=0.95,
                evidence=[
                    Evidence(
                        source="advisory-scan",
                        snippet="No known vulnerabilities matched current dependencies",
                    )
                ],
                remediation="現時点で既知脆弱性は検出されていません。継続的に監視してください。",
                context={
                    "dependencies_total": len(dependencies),
                    "dependencies_scanned": scanned_dependencies,
                    "dependencies_without_version": unpinned_dependencies,
                },
                status="MITIGATED",
            )
        ]

    @staticmethod
    def _severity_from_signal(cvss: float | None, kev_flag: bool) -> Severity:
        if cvss is not None:
            if cvss >= 9.0:
                return Severity.CRITICAL
            if cvss >= 7.0:
                return Severity.HIGH
            if cvss >= 4.0:
                return Severity.MEDIUM
            if cvss > 0:
                return Severity.LOW

        # CVSS未取得時は過小評価を避けてMedium、
        # KEVは最低Highへ昇格
        if kev_flag:
            return Severity.HIGH
        return Severity.MEDIUM

    @staticmethod
    def _collect_dependencies_with_sources(
        target: Path,
    ) -> dict[tuple[str, str], dict[str, str | set[str] | None]]:
        deps: dict[tuple[str, str], dict[str, str | set[str] | None]] = {}

        def merge(
            items: list[tuple[str, str, str | None]],
            source_file: Path,
        ) -> None:
            for name, ecosystem, version in items:
                key = (ecosystem, name)
                current = deps.get(key)
                if current is None:
                    deps[key] = {"version": version, "files": {str(source_file)}}
                    continue

                files = current.get("files")
                if isinstance(files, set):
                    files.add(str(source_file))

                current_version = current.get("version")
                if (
                    not isinstance(current_version, str) or not current_version
                ) and version:
                    current["version"] = version

        req = target / "requirements.txt"
        if req.exists() and req.is_file():
            merge(A0_SbomFullAnalysisRule._parse_requirements(req), req)

        pyproject = target / "pyproject.toml"
        if pyproject.exists() and pyproject.is_file():
            merge(
                A0_SbomFullAnalysisRule._parse_pyproject_dependencies(pyproject),
                pyproject,
            )

        package_json = target / "package.json"
        if package_json.exists() and package_json.is_file():
            merge(
                A0_SbomFullAnalysisRule._parse_package_json_direct_dependencies(
                    package_json
                ),
                package_json,
            )

        package_lock = target / "package-lock.json"
        if package_lock.exists() and package_lock.is_file():
            merge(
                A0_SbomFullAnalysisRule._parse_package_lock_dependencies(package_lock),
                package_lock,
            )

        poetry_lock = target / "poetry.lock"
        if poetry_lock.exists() and poetry_lock.is_file():
            merge(
                A0_SbomFullAnalysisRule._parse_poetry_lock_dependencies(poetry_lock),
                poetry_lock,
            )

        return deps


class A2_UnpinnedDependencyVersionsRule(_SkeletonRule):
    """A-2: Unpinned dependency versions."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="A-2", category="A", title="Unpinned dependency versions"
        )

    def evaluate(self, target: Path, mode: str) -> list[RiskRecord]:
        manifests = self._collect_manifest_dependencies(target)
        lock_by_ecosystem = self._detect_lock_files(target)

        findings: list[RiskRecord] = []
        unpinned_count = 0
        pinned_count = 0

        for dep in manifests:
            spec_raw = dep.get("version_spec")
            spec = spec_raw.strip() if isinstance(spec_raw, str) else None
            ecosystem = str(dep.get("ecosystem") or "unknown")
            package = str(dep.get("package") or "")
            is_dev = bool(dep.get("is_dev"))
            file = str(dep.get("file") or "")
            line = dep.get("line")

            if self._is_pinned_version_spec(ecosystem, spec):
                pinned_count += 1
                continue

            unpinned_count += 1
            lock_present = lock_by_ecosystem.get(ecosystem, False)

            severity = Severity.LOW if lock_present else Severity.MEDIUM
            if is_dev and severity == Severity.MEDIUM:
                severity = Severity.LOW

            if self._should_escalate_to_high(
                ecosystem=ecosystem,
                package=package,
                version_spec=spec,
                file=file,
            ):
                severity = Severity.HIGH

            confidence = 0.85
            if isinstance(line, int) and line > 0 and spec:
                confidence = 0.95
            elif file and spec:
                confidence = 0.8

            evidence_payload = {
                "file": file or None,
                "line": line if isinstance(line, int) else None,
                "package": package,
                "version_spec": spec,
                "ecosystem": ecosystem,
                "lock_present": lock_present,
            }

            findings.append(
                RiskRecord(
                    category=self.category,
                    rule_id=self.rule_id,
                    severity=severity,
                    risk_score=self._risk_score_from_severity(severity),
                    confidence=confidence,
                    evidence=[
                        Evidence(
                            file=file or None,
                            line=line if isinstance(line, int) else None,
                            source="manifest-version-spec",
                            snippet=json.dumps(
                                evidence_payload,
                                ensure_ascii=False,
                            ),
                        )
                    ],
                    remediation=(
                        "依存バージョンを固定し、ロックファイルをコミットしてください。"
                        "CIで manifest/lock の整合性チェックを必須化してください。"
                    ),
                    context={
                        "package_name": package,
                        "version_spec": spec,
                        "ecosystem": ecosystem,
                        "lock_present": lock_present,
                        "is_dev_dependency": is_dev,
                        "mode": mode,
                    },
                    source="rule-engine",
                    coverage={
                        "level": self._coverage_level(
                            manifest_count=len(manifests),
                            lock_detected=any(lock_by_ecosystem.values()),
                        ),
                        "manifest_count": len(manifests),
                        "lock_detected": any(lock_by_ecosystem.values()),
                    },
                )
            )

        if findings:
            return findings

        return [
            RiskRecord(
                category=self.category,
                rule_id=self.rule_id,
                severity=Severity.INFO,
                confidence=0.95,
                evidence=[
                    Evidence(
                        source="manifest-version-spec",
                        snippet="No unpinned dependency versions detected",
                    )
                ],
                remediation=(
                    "依存バージョン固定状態は良好です。"
                    "依存更新時も lock file と併せて継続確認してください。"
                ),
                context={
                    "dependencies_total": len(manifests),
                    "dependencies_pinned": pinned_count,
                    "dependencies_unpinned": unpinned_count,
                    "lock_by_ecosystem": lock_by_ecosystem,
                },
                status="MITIGATED",
                coverage={
                    "level": self._coverage_level(
                        manifest_count=len(manifests),
                        lock_detected=any(lock_by_ecosystem.values()),
                    ),
                    "manifest_count": len(manifests),
                    "lock_detected": any(lock_by_ecosystem.values()),
                },
            )
        ]

    @staticmethod
    def _risk_score_from_severity(severity: Severity) -> float:
        if severity == Severity.CRITICAL:
            return 10.0
        if severity == Severity.HIGH:
            return 6.0
        if severity == Severity.MEDIUM:
            return 3.0
        if severity == Severity.LOW:
            return 1.0
        return 0.0

    @staticmethod
    def _coverage_level(manifest_count: int, lock_detected: bool) -> str:
        if manifest_count <= 0:
            return "NONE"
        if lock_detected:
            return "FULL"
        return "PARTIAL"

    @staticmethod
    def _is_pinned_version_spec(ecosystem: str, version_spec: str | None) -> bool:
        if not isinstance(version_spec, str):
            return False

        spec = version_spec.strip()
        if not spec:
            return False

        lowered = spec.lower()
        if lowered in {"*", "latest"}:
            return False

        if ecosystem == "docker":
            return "@sha256:" in lowered

        # Python pinned: ==x.y.z
        if ecosystem == "pypi":
            return bool(re.match(r"^==\s*[A-Za-z0-9_.+\-]+$", spec))

        # npm pinned: exact semver like 1.2.3 (v-prefix tolerated)
        if ecosystem == "npm":
            return bool(
                re.match(r"^v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9_.\-]+)?$", spec)
            )

        # Generic pinned: single version-like token without range operators.
        if any(token in spec for token in ("^", "~", "*", ">", "<", "=", "||", " ")):
            return False
        return bool(re.match(r"^[A-Za-z0-9_.+\-]+$", spec))

    @staticmethod
    def _should_escalate_to_high(
        ecosystem: str,
        package: str,
        version_spec: str | None,
        file: str,
    ) -> bool:
        lowered_package = package.lower()
        lowered_spec = (version_spec or "").lower()
        lowered_file = file.lower()

        if (
            ecosystem == "docker"
            and not A2_UnpinnedDependencyVersionsRule._is_pinned_version_spec(
                ecosystem,
                version_spec,
            )
        ):
            return True

        sensitive_keywords = (
            "auth",
            "oauth",
            "jwt",
            "crypto",
            "tls",
            "ssl",
            "http",
            "requests",
            "axios",
            "ci",
            "deploy",
            "pipeline",
        )
        if any(keyword in lowered_package for keyword in sensitive_keywords):
            return True

        if any(
            keyword in lowered_file
            for keyword in ("workflow", ".github/", "dockerfile")
        ):
            return True

        return lowered_spec == "latest"

    @staticmethod
    def _detect_lock_files(target: Path) -> dict[str, bool]:
        return {
            "pypi": any(
                (target / name).exists()
                for name in ("poetry.lock", "Pipfile.lock", "requirements.lock")
            ),
            "npm": any(
                (target / name).exists()
                for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
            ),
            "ruby": (target / "Gemfile.lock").exists(),
            "go": (target / "go.sum").exists(),
            "cargo": (target / "Cargo.lock").exists(),
            "java": False,
            "docker": False,
        }

    def _collect_manifest_dependencies(
        self,
        target: Path,
    ) -> list[dict[str, str | int | bool | None]]:
        deps: list[dict[str, str | int | bool | None]] = []

        req = target / "requirements.txt"
        if req.exists() and req.is_file():
            deps.extend(self._parse_requirements_manifest(req))

        pyproject = target / "pyproject.toml"
        if pyproject.exists() and pyproject.is_file():
            deps.extend(self._parse_pyproject_manifest(pyproject))

        pipfile = target / "Pipfile"
        if pipfile.exists() and pipfile.is_file():
            deps.extend(self._parse_pipfile_manifest(pipfile))

        package_json = target / "package.json"
        if package_json.exists() and package_json.is_file():
            deps.extend(self._parse_package_json_manifest(package_json))

        gemfile = target / "Gemfile"
        if gemfile.exists() and gemfile.is_file():
            deps.extend(self._parse_gemfile_manifest(gemfile))

        pom = target / "pom.xml"
        if pom.exists() and pom.is_file():
            deps.extend(self._parse_pom_manifest(pom))

        gradle = target / "build.gradle"
        if gradle.exists() and gradle.is_file():
            deps.extend(self._parse_gradle_manifest(gradle))

        go_mod = target / "go.mod"
        if go_mod.exists() and go_mod.is_file():
            deps.extend(self._parse_go_mod_manifest(go_mod))

        cargo_toml = target / "Cargo.toml"
        if cargo_toml.exists() and cargo_toml.is_file():
            deps.extend(self._parse_cargo_manifest(cargo_toml))

        dockerfile = target / "Dockerfile"
        if dockerfile.exists() and dockerfile.is_file():
            deps.extend(self._parse_dockerfile_manifest(dockerfile))

        return deps

    @staticmethod
    def _parse_requirements_manifest(
        path: Path,
    ) -> list[dict[str, str | int | bool | None]]:
        items: list[dict[str, str | int | bool | None]] = []
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for idx, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", line)
            if not match:
                continue
            package = match.group(1).lower()
            rest = match.group(2).strip()
            version_spec = rest or None
            items.append(
                {
                    "file": str(path),
                    "line": idx,
                    "package": package,
                    "version_spec": version_spec,
                    "ecosystem": "pypi",
                    "is_dev": False,
                }
            )
        return items

    @staticmethod
    def _parse_pyproject_manifest(
        path: Path,
    ) -> list[dict[str, str | int | bool | None]]:
        items: list[dict[str, str | int | bool | None]] = []
        try:
            import tomllib
        except ModuleNotFoundError:
            return items

        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except (OSError, tomllib.TOMLDecodeError):
            return items

        project = data.get("project", {})
        dependencies = project.get("dependencies", [])
        if isinstance(dependencies, list):
            for dep in dependencies:
                if not isinstance(dep, str):
                    continue
                row = dep.strip()
                if not row:
                    continue
                match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", row)
                if not match:
                    continue
                package = match.group(1).lower()
                spec = match.group(2).strip() or None
                items.append(
                    {
                        "file": str(path),
                        "line": A2_UnpinnedDependencyVersionsRule._find_line(
                            lines, package
                        ),
                        "package": package,
                        "version_spec": spec,
                        "ecosystem": "pypi",
                        "is_dev": False,
                    }
                )

        poetry = data.get("tool", {}).get("poetry", {})
        for key, is_dev in (("dependencies", False), ("group", False)):
            value = poetry.get(key)
            if key == "dependencies" and isinstance(value, dict):
                for name, raw_spec in value.items():
                    package = str(name).lower()
                    if package == "python":
                        continue
                    spec = A2_UnpinnedDependencyVersionsRule._normalize_poetry_spec(
                        raw_spec
                    )
                    items.append(
                        {
                            "file": str(path),
                            "line": A2_UnpinnedDependencyVersionsRule._find_line(
                                lines, package
                            ),
                            "package": package,
                            "version_spec": spec,
                            "ecosystem": "pypi",
                            "is_dev": is_dev,
                        }
                    )
            if key == "group" and isinstance(value, dict):
                for group_name, group_data in value.items():
                    if not isinstance(group_data, dict):
                        continue
                    deps = group_data.get("dependencies")
                    if not isinstance(deps, dict):
                        continue
                    dev_group = str(group_name).lower() == "dev"
                    for name, raw_spec in deps.items():
                        package = str(name).lower()
                        spec = A2_UnpinnedDependencyVersionsRule._normalize_poetry_spec(
                            raw_spec
                        )
                        items.append(
                            {
                                "file": str(path),
                                "line": A2_UnpinnedDependencyVersionsRule._find_line(
                                    lines, package
                                ),
                                "package": package,
                                "version_spec": spec,
                                "ecosystem": "pypi",
                                "is_dev": dev_group,
                            }
                        )
        return items

    @staticmethod
    def _normalize_poetry_spec(value: object) -> str | None:
        if isinstance(value, str):
            return value.strip() or None
        if isinstance(value, Mapping):
            mapped = cast(Mapping[str, object], value)
            raw = mapped.get("version")
            if isinstance(raw, str):
                return raw.strip() or None
        return None

    @staticmethod
    def _parse_pipfile_manifest(path: Path) -> list[dict[str, str | int | bool | None]]:
        items: list[dict[str, str | int | bool | None]] = []
        try:
            import tomllib
        except ModuleNotFoundError:
            return items

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            data = tomllib.loads(text)
            lines = text.splitlines()
        except (OSError, tomllib.TOMLDecodeError):
            return items

        for section, is_dev in (("packages", False), ("dev-packages", True)):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for name, raw in deps.items():
                package = str(name).lower()
                spec = str(raw).strip() if raw is not None else None
                items.append(
                    {
                        "file": str(path),
                        "line": A2_UnpinnedDependencyVersionsRule._find_line(
                            lines, package
                        ),
                        "package": package,
                        "version_spec": spec or None,
                        "ecosystem": "pypi",
                        "is_dev": is_dev,
                    }
                )
        return items

    @staticmethod
    def _parse_package_json_manifest(
        path: Path,
    ) -> list[dict[str, str | int | bool | None]]:
        items: list[dict[str, str | int | bool | None]] = []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(text)
            lines = text.splitlines()
        except (json.JSONDecodeError, OSError):
            return items

        for section, is_dev in (
            ("dependencies", False),
            ("devDependencies", True),
            ("optionalDependencies", False),
            ("peerDependencies", False),
        ):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for name, raw_spec in deps.items():
                package = str(name).lower()
                spec = str(raw_spec).strip() if raw_spec is not None else None
                items.append(
                    {
                        "file": str(path),
                        "line": A2_UnpinnedDependencyVersionsRule._find_line(
                            lines, f'"{name}"'
                        ),
                        "package": package,
                        "version_spec": spec or None,
                        "ecosystem": "npm",
                        "is_dev": is_dev,
                    }
                )
        return items

    @staticmethod
    def _parse_gemfile_manifest(path: Path) -> list[dict[str, str | int | bool | None]]:
        items: list[dict[str, str | int | bool | None]] = []
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        in_dev_group = False
        for idx, raw in enumerate(lines, start=1):
            row = raw.strip()
            if re.match(r"^group\s+:development", row):
                in_dev_group = True
            if row == "end":
                in_dev_group = False

            match = re.match(
                r"^gem\s+[\"']([^\"']+)[\"']\s*(?:,\s*[\"']([^\"']+)[\"'])?", row
            )
            if not match:
                continue
            package = match.group(1).lower()
            spec = match.group(2).strip() if match.group(2) else None
            items.append(
                {
                    "file": str(path),
                    "line": idx,
                    "package": package,
                    "version_spec": spec,
                    "ecosystem": "ruby",
                    "is_dev": in_dev_group,
                }
            )
        return items

    @staticmethod
    def _parse_pom_manifest(path: Path) -> list[dict[str, str | int | bool | None]]:
        items: list[dict[str, str | int | bool | None]] = []
        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, ET.ParseError):
            return items

        for dep in root.findall(".//{*}dependency"):
            artifact = dep.find("{*}artifactId")
            version = dep.find("{*}version")
            scope = dep.find("{*}scope")
            if artifact is None or artifact.text is None:
                continue
            package = artifact.text.strip().lower()
            spec = (
                version.text.strip() if version is not None and version.text else None
            )
            is_dev = bool(
                scope is not None and scope.text and scope.text.strip() == "test"
            )
            items.append(
                {
                    "file": str(path),
                    "line": None,
                    "package": package,
                    "version_spec": spec,
                    "ecosystem": "java",
                    "is_dev": is_dev,
                }
            )
        return items

    @staticmethod
    def _parse_gradle_manifest(path: Path) -> list[dict[str, str | int | bool | None]]:
        items: list[dict[str, str | int | bool | None]] = []
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        pattern = re.compile(
            r"^(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s+['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]"
        )
        for idx, raw in enumerate(lines, start=1):
            row = raw.strip()
            match = pattern.match(row)
            if not match:
                continue
            config = match.group(1)
            artifact = match.group(3).lower()
            version = match.group(4).strip()
            items.append(
                {
                    "file": str(path),
                    "line": idx,
                    "package": artifact,
                    "version_spec": version,
                    "ecosystem": "java",
                    "is_dev": config.startswith("test"),
                }
            )
        return items

    @staticmethod
    def _parse_go_mod_manifest(path: Path) -> list[dict[str, str | int | bool | None]]:
        items: list[dict[str, str | int | bool | None]] = []
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        in_require_block = False
        for idx, raw in enumerate(lines, start=1):
            row = raw.strip()
            if row.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block and row == ")":
                in_require_block = False
                continue

            if row.startswith("require "):
                part = row[len("require ") :].strip()
                cols = part.split()
                if len(cols) >= 2:
                    items.append(
                        {
                            "file": str(path),
                            "line": idx,
                            "package": cols[0].lower(),
                            "version_spec": cols[1],
                            "ecosystem": "go",
                            "is_dev": False,
                        }
                    )
                continue

            if in_require_block and row and not row.startswith("//"):
                cols = row.split()
                if len(cols) >= 2:
                    items.append(
                        {
                            "file": str(path),
                            "line": idx,
                            "package": cols[0].lower(),
                            "version_spec": cols[1],
                            "ecosystem": "go",
                            "is_dev": "indirect" in row,
                        }
                    )
        return items

    @staticmethod
    def _parse_cargo_manifest(path: Path) -> list[dict[str, str | int | bool | None]]:
        items: list[dict[str, str | int | bool | None]] = []
        try:
            import tomllib
        except ModuleNotFoundError:
            return items

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            data = tomllib.loads(text)
            lines = text.splitlines()
        except (OSError, tomllib.TOMLDecodeError):
            return items

        for section, is_dev in (
            ("dependencies", False),
            ("dev-dependencies", True),
            ("build-dependencies", False),
        ):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for name, value in deps.items():
                package = str(name).lower()
                spec: str | None = None
                if isinstance(value, str):
                    spec = value.strip() or None
                elif isinstance(value, dict):
                    raw = value.get("version")
                    if isinstance(raw, str):
                        spec = raw.strip() or None
                items.append(
                    {
                        "file": str(path),
                        "line": A2_UnpinnedDependencyVersionsRule._find_line(
                            lines, package
                        ),
                        "package": package,
                        "version_spec": spec,
                        "ecosystem": "cargo",
                        "is_dev": is_dev,
                    }
                )
        return items

    @staticmethod
    def _parse_dockerfile_manifest(
        path: Path,
    ) -> list[dict[str, str | int | bool | None]]:
        items: list[dict[str, str | int | bool | None]] = []
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for idx, raw in enumerate(lines, start=1):
            row = raw.strip()
            match = re.match(r"^FROM\s+([^\s]+)", row, flags=re.IGNORECASE)
            if not match:
                continue
            image_ref = match.group(1)
            image_name = image_ref
            version_spec: str | None = None
            if "@sha256:" in image_ref.lower():
                image_name = image_ref.split("@", 1)[0]
                version_spec = image_ref.split("@", 1)[1]
            elif ":" in image_ref:
                image_name, version_spec = image_ref.rsplit(":", 1)
            else:
                version_spec = "latest"

            items.append(
                {
                    "file": str(path),
                    "line": idx,
                    "package": image_name.lower(),
                    "version_spec": version_spec,
                    "ecosystem": "docker",
                    "is_dev": False,
                }
            )
        return items

    @staticmethod
    def _find_line(lines: list[str], needle: str) -> int | None:
        low_needle = needle.lower()
        for idx, line in enumerate(lines, start=1):
            if low_needle in line.lower():
                return idx
        return None


class A3_UnsignedArtifactsRule(_SkeletonRule):
    """A-3: Signature verification missing for artifacts."""

    def __init__(self) -> None:
        super().__init__(rule_id="A-3", category="A", title="Unsigned artifacts")


class B1_GithubActionsShaPinningRule(_SkeletonRule):
    """B-1: GitHub Actions SHA pinning."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="B-1", category="B", title="GitHub Actions SHA pinning"
        )


class B2_OverPrivilegedWorkflowRule(_SkeletonRule):
    """B-2: Over-privileged workflow permissions."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="B-2", category="B", title="Over-privileged workflow permissions"
        )


class B3_UnpinnedDockerDigestRule(_SkeletonRule):
    """B-3: Docker image digest not pinned."""

    def __init__(self) -> None:
        super().__init__(rule_id="B-3", category="B", title="Unpinned Docker digest")


class B4_CurlPipeBashRule(_SkeletonRule):
    """B-4: Direct execution via curl|bash."""

    def __init__(self) -> None:
        super().__init__(rule_id="B-4", category="B", title="curl | bash execution")


class C1_ContainerRunsAsRootRule(_SkeletonRule):
    """C-1: Container runs as root."""

    def __init__(self) -> None:
        super().__init__(rule_id="C-1", category="C", title="Container runs as root")


class C2_SecretsExposureRule(_SkeletonRule):
    """C-2: Secrets exposure in repository contents."""

    def __init__(self) -> None:
        super().__init__(rule_id="C-2", category="C", title="Secrets exposure")


class C3_DangerousApiUsageRule(_SkeletonRule):
    """C-3: Dangerous API usage."""

    def __init__(self) -> None:
        super().__init__(rule_id="C-3", category="C", title="Dangerous API usage")


class C4_CorsWildcardRule(_SkeletonRule):
    """C-4: Wildcard CORS configuration."""

    def __init__(self) -> None:
        super().__init__(rule_id="C-4", category="C", title="CORS wildcard")


class D1_MaintenanceInactivityRule(_SkeletonRule):
    """D-1: Maintenance inactivity risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="D-1", category="D", title="Maintenance inactivity")


class D2_BusFactorOneRule(_SkeletonRule):
    """D-2: Bus factor one risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="D-2", category="D", title="Bus factor 1")


class D3_NoSecurityOperationRule(_SkeletonRule):
    """D-3: Missing security operations."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="D-3", category="D", title="Missing security operations"
        )


class D4_PatchDelayRule(_SkeletonRule):
    """D-4: Delayed remediation risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="D-4", category="D", title="Patch delay")


class E1_GplAgplLicenseRule(_SkeletonRule):
    """E-1: GPL/AGPL license risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="E-1", category="E", title="GPL/AGPL license risk")


class E2_IncompatibleLicenseMixRule(_SkeletonRule):
    """E-2: Incompatible license combination risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="E-2", category="E", title="Incompatible license mix")


class E3_UndefinedLicenseRule(_SkeletonRule):
    """E-3: Undefined license risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="E-3", category="E", title="Undefined license")


class F1_DebugEnabledRule(_SkeletonRule):
    """F-1: Debug mode enabled."""

    def __init__(self) -> None:
        super().__init__(rule_id="F-1", category="F", title="Debug mode enabled")


class F2_HttpOnlyCommunicationRule(_SkeletonRule):
    """F-2: HTTP-only communication."""

    def __init__(self) -> None:
        super().__init__(rule_id="F-2", category="F", title="HTTP-only communication")


class F3_AdminEndpointExposedRule(_SkeletonRule):
    """F-3: Potential public exposure of admin endpoint."""

    def __init__(self) -> None:
        super().__init__(rule_id="F-3", category="F", title="Admin endpoint exposure")


# Backward-compatible aliases used by registry.py
A0SbomFullAnalysisRule = A0_SbomFullAnalysisRule
A1KnownVulnerabilitiesRule = A1_KnownVulnerabilitiesRule
A2UnpinnedDependencyVersionsRule = A2_UnpinnedDependencyVersionsRule
A3UnsignedArtifactsRule = A3_UnsignedArtifactsRule
B1GithubActionsShaPinningRule = B1_GithubActionsShaPinningRule
B2OverPrivilegedWorkflowRule = B2_OverPrivilegedWorkflowRule
B3UnpinnedDockerDigestRule = B3_UnpinnedDockerDigestRule
B4CurlPipeBashRule = B4_CurlPipeBashRule
C1ContainerRunsAsRootRule = C1_ContainerRunsAsRootRule
C2SecretsExposureRule = C2_SecretsExposureRule
C3DangerousApiUsageRule = C3_DangerousApiUsageRule
C4CorsWildcardRule = C4_CorsWildcardRule
D1MaintenanceInactivityRule = D1_MaintenanceInactivityRule
D2BusFactorOneRule = D2_BusFactorOneRule
D3NoSecurityOperationRule = D3_NoSecurityOperationRule
D4PatchDelayRule = D4_PatchDelayRule
E1GplAgplLicenseRule = E1_GplAgplLicenseRule
E2IncompatibleLicenseMixRule = E2_IncompatibleLicenseMixRule
E3UndefinedLicenseRule = E3_UndefinedLicenseRule
F1DebugEnabledRule = F1_DebugEnabledRule
F2HttpOnlyCommunicationRule = F2_HttpOnlyCommunicationRule
F3AdminEndpointExposedRule = F3_AdminEndpointExposedRule
