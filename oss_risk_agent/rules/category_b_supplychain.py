from pathlib import Path
from typing import List
import re
import yaml
import json
import subprocess

from ..core.models import Rule, RiskRecord, Severity


class B1UnpinnedActionsRule(Rule):
    @property
    def category(self) -> str:
        return "B-1"

    @property
    def name(self) -> str:
        return "GitHub Actionsのバージョン未固定"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        workflows_dir = repo_path / ".github" / "workflows"
        if workflows_dir.exists() and workflows_dir.is_dir():
            for yaml_file in workflows_dir.glob("*.yml"):
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)

                    if not isinstance(data, dict):
                        continue

                    jobs = data.get("jobs", {})
                    for job_name, job_data in jobs.items():
                        steps = job_data.get("steps", [])
                        for i, step in enumerate(steps):
                            uses = step.get("uses")
                            if uses and "@" in uses:
                                part_after_at = uses.split("@", 1)[1]
                                # SHA1ハッシュは通常40桁の16進数
                                if not re.match(r"^[0-9a-f]{40}$", part_after_at):
                                    risks.append(
                                        RiskRecord(
                                            category=self.category,
                                            name=self.name,
                                            severity=Severity.HIGH,
                                            description=f"GitHub Actions '{uses}' はコミットSHAで固定されていません（タグ参照など）。",
                                            target_file=str(
                                                yaml_file.relative_to(repo_path)
                                            ),
                                            evidence=uses,
                                        )
                                    )
                except (yaml.YAMLError, OSError, UnicodeDecodeError):
                    continue

        return risks


class B2DockerLatestRule(Rule):
    @property
    def category(self) -> str:
        return "B-2"

    @property
    def name(self) -> str:
        return "Dockerベースイメージがlatest指定"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        for dockerfile in repo_path.rglob("Dockerfile*"):
            try:
                with open(dockerfile, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        line = line.strip()
                        if line.upper().startswith("FROM "):
                            parts = line.split()
                            if len(parts) >= 2:
                                image_name = parts[1]
                                # as builder などの別名指定は無視
                                if ":" not in image_name or image_name.endswith(
                                    ":latest"
                                ):
                                    risks.append(
                                        RiskRecord(
                                            category=self.category,
                                            name=self.name,
                                            severity=Severity.HIGH,
                                            description=f"Dockerベースイメージ '{image_name}' はlatest指定またはタグ未指定です。",
                                            target_file=str(
                                                dockerfile.relative_to(repo_path)
                                            ),
                                            line_number=i,
                                            evidence=line,
                                        )
                                    )
            except (OSError, UnicodeDecodeError):
                continue
        return risks


class B3DirectExecutionRule(Rule):
    @property
    def category(self) -> str:
        return "B-3"

    @property
    def name(self) -> str:
        return "curl | bash 等の直接実行"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []

        target_files = []
        target_files.extend(repo_path.rglob("Dockerfile*"))
        target_files.extend(repo_path.rglob("*.sh"))
        target_files.extend(repo_path.rglob("*.bash"))
        target_files.extend(repo_path.rglob("*.py"))
        target_files.extend(repo_path.rglob("*.js"))
        target_files.extend(repo_path.rglob("*.ts"))

        # workflows
        workflows_dir = repo_path / ".github" / "workflows"
        if workflows_dir.exists():
            target_files.extend(workflows_dir.rglob("*.yml"))
            target_files.extend(workflows_dir.rglob("*.yaml"))

        # 同一ファイルの重複解析を防ぐ
        target_files = list(dict.fromkeys(target_files))

        pattern = re.compile(r"(curl|wget)[\s\S]+?\|[\s\S]*(bash|sh|zsh)")

        for file in target_files:
            try:
                # Pythonファイルの特別なAST解析
                if file.suffix == ".py":
                    import ast

                    try:
                        with open(file, "r", encoding="utf-8") as f:
                            source = f.read()
                        tree = ast.parse(source)

                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call):
                                # os.system("...") の検知
                                if (
                                    isinstance(node.func, ast.Attribute)
                                    and getattr(node.func.value, "id", "") == "os"
                                    and node.func.attr == "system"
                                ):
                                    if (
                                        node.args
                                        and isinstance(node.args[0], ast.Constant)
                                        and isinstance(node.args[0].value, str)
                                    ):
                                        if pattern.search(node.args[0].value):
                                            risks.append(
                                                RiskRecord(
                                                    category=self.category,
                                                    name=self.name,
                                                    severity=Severity.CRITICAL,
                                                    description=f"os.system内で外部スクリプト(curl/wget等)を取得しパイプでシェルに渡しています。",
                                                    target_file=str(
                                                        file.relative_to(repo_path)
                                                    ),
                                                    line_number=node.lineno,
                                                    evidence=node.args[0].value,
                                                )
                                            )
                                # subprocess.run / Popen 等の検知 (shell=Trueの場合)
                                elif (
                                    isinstance(node.func, ast.Attribute)
                                    and getattr(node.func.value, "id", "")
                                    == "subprocess"
                                    and node.func.attr
                                    in [
                                        "run",
                                        "Popen",
                                        "call",
                                        "check_call",
                                        "check_output",
                                    ]
                                ):
                                    is_shell_true = any(
                                        kw.arg == "shell"
                                        and isinstance(kw.value, ast.Constant)
                                        and kw.value.value is True
                                        for kw in node.keywords
                                    )
                                    if is_shell_true and node.args:
                                        if isinstance(
                                            node.args[0], ast.Constant
                                        ) and isinstance(node.args[0].value, str):
                                            if pattern.search(node.args[0].value):
                                                risks.append(
                                                    RiskRecord(
                                                        category=self.category,
                                                        name=self.name,
                                                        severity=Severity.CRITICAL,
                                                        description=f"subprocess({node.func.attr})のshell引数で外部スクリプトを取得しパイプで実行しています。",
                                                        target_file=str(
                                                            file.relative_to(repo_path)
                                                        ),
                                                        line_number=node.lineno,
                                                        evidence=node.args[0].value,
                                                    )
                                                )
                    except (SyntaxError, ValueError, OSError, UnicodeDecodeError):
                        continue  # AST Parse Error 等はスキップ

                # JS/TSファイルのコンテキスト考慮の疑似AST解析
                elif file.suffix in [".js", ".jsx", ".ts", ".tsx"]:
                    from ..utils.js_parser import check_direct_exec_in_js

                    suspicious_lines = check_direct_exec_in_js(file)
                    for ln in suspicious_lines:
                        with open(file, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                            evidence = lines[ln - 1].strip() if ln <= len(lines) else ""
                        risks.append(
                            RiskRecord(
                                category=self.category,
                                name=self.name,
                                severity=Severity.CRITICAL,
                                description=f"child_process.exec等で外部スクリプト(curl/wget等)を取得しパイプでシェルに渡しています。",
                                target_file=str(file.relative_to(repo_path)),
                                line_number=ln,
                                evidence=evidence,
                            )
                        )

                # 従来のテキストベースの解析 (Dockerfile, sh, bash, ymlなど)
                else:
                    with open(file, "r", encoding="utf-8") as f:
                        for i, line in enumerate(f, 1):
                            if pattern.search(line):
                                risks.append(
                                    RiskRecord(
                                        category=self.category,
                                        name=self.name,
                                        severity=Severity.CRITICAL,
                                        description="外部スクリプト(curl/wget等)を取得し、そのままパイプでシェルに渡して実行しています。",
                                        target_file=str(file.relative_to(repo_path)),
                                        line_number=i,
                                        evidence=line.strip(),
                                    )
                                )
            except (OSError, UnicodeDecodeError):
                continue
        return risks


class B4ContainerBaseImageCveRule(Rule):
    @property
    def category(self) -> str:
        return "B-4"

    @property
    def name(self) -> str:
        return "コンテナベースイメージCVE検出"

    def _extract_base_images(self, repo_path: Path) -> List[tuple[str, str, int]]:
        images: List[tuple[str, str, int]] = []
        for dockerfile in repo_path.rglob("Dockerfile*"):
            try:
                with open(dockerfile, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        s = line.strip()
                        if s.upper().startswith("FROM "):
                            parts = s.split()
                            if len(parts) >= 2:
                                images.append(
                                    (
                                        str(dockerfile.relative_to(repo_path)),
                                        parts[1],
                                        i,
                                    )
                                )
            except (OSError, UnicodeDecodeError):
                continue
        return images

    def _scan_with_trivy(self, image: str) -> dict:
        cmd = [
            "trivy",
            "image",
            "--quiet",
            "--format",
            "json",
            image,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except Exception:
            return {}
        if proc.returncode != 0:
            return {}
        try:
            return json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return {}

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks: List[RiskRecord] = []
        base_images = self._extract_base_images(repo_path)

        for dockerfile, image, line_no in base_images:
            trivy_json = self._scan_with_trivy(image)
            vulns = []
            for result in trivy_json.get("Results", []) or []:
                vulns.extend(result.get("Vulnerabilities", []) or [])

            critical = [v for v in vulns if v.get("Severity") == "CRITICAL"]
            high = [v for v in vulns if v.get("Severity") == "HIGH"]

            if critical:
                severity = Severity.CRITICAL
            elif len(high) >= 3:
                severity = Severity.HIGH
            elif 1 <= len(high) <= 2:
                severity = Severity.MEDIUM
            else:
                continue

            evidence = ", ".join(
                [f"{v.get('VulnerabilityID')}:{v.get('Severity')}" for v in vulns[:10]]
            )
            risks.append(
                RiskRecord(
                    category=self.category,
                    name=self.name,
                    severity=severity,
                    description=f"ベースイメージ '{image}' にOSパッケージ脆弱性が検出されました。",
                    target_file=dockerfile,
                    line_number=line_no,
                    evidence=evidence or image,
                )
            )

        return risks


class B5GithubActionsPermissionsRule(Rule):
    @property
    def category(self) -> str:
        return "B-5"

    @property
    def name(self) -> str:
        return "GitHub Actions権限過剰"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks: List[RiskRecord] = []
        workflows_dir = repo_path / ".github" / "workflows"
        if not workflows_dir.exists():
            return risks

        for yaml_file in workflows_dir.glob("*.yml"):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            except (OSError, UnicodeDecodeError, yaml.YAMLError):
                continue

            rel = str(yaml_file.relative_to(repo_path))
            permissions = data.get("permissions")
            if permissions is None:
                risks.append(
                    RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=Severity.MEDIUM,
                        description="workflowでpermissionsが未定義です。",
                        target_file=rel,
                        evidence="permissions: <undefined>",
                    )
                )
            elif permissions == "write-all":
                risks.append(
                    RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=Severity.HIGH,
                        description="workflowでwrite-all権限が指定されています。",
                        target_file=rel,
                        evidence="permissions: write-all",
                    )
                )
            elif isinstance(permissions, dict):
                for scope, value in permissions.items():
                    if str(value).lower() == "write":
                        risks.append(
                            RiskRecord(
                                category=self.category,
                                name=self.name,
                                severity=Severity.HIGH,
                                description="GITHUB_TOKENに過剰なwriteスコープが付与されています。",
                                target_file=rel,
                                evidence=f"permissions.{scope}: write",
                            )
                        )
                        break

        return risks


class B6ArtifactSignatureVerificationRule(Rule):
    @property
    def category(self) -> str:
        return "B-6"

    @property
    def name(self) -> str:
        return "Artifact署名検証"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks: List[RiskRecord] = []

        has_docker = any(repo_path.rglob("Dockerfile*"))
        has_npm = (repo_path / "package.json").exists()
        has_release = (repo_path / ".github" / "workflows").exists()

        cosign_pub = repo_path / "cosign.pub"
        provenance = repo_path / "provenance.json"
        slsa = repo_path / "slsa-provenance.json"

        if (has_docker or has_npm or has_release) and not cosign_pub.exists():
            risks.append(
                RiskRecord(
                    category=self.category,
                    name=self.name,
                    severity=Severity.MEDIUM,
                    description="cosign署名が確認できません。",
                    target_file="artifacts",
                    evidence="cosign.pub not found",
                )
            )

        if not provenance.exists():
            risks.append(
                RiskRecord(
                    category=self.category,
                    name=self.name,
                    severity=Severity.LOW,
                    description="provenanceが未確認です。",
                    target_file="artifacts",
                    evidence="provenance.json not found",
                )
            )

        if not slsa.exists():
            risks.append(
                RiskRecord(
                    category=self.category,
                    name=self.name,
                    severity=Severity.LOW,
                    description="SLSA level < 2 または未確認です。",
                    target_file="artifacts",
                    evidence="slsa-provenance.json not found",
                )
            )

        return risks
