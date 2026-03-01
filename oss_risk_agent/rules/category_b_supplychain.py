from pathlib import Path
from typing import List
import re
import yaml

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
