from pathlib import Path
from typing import List
import re

from ..core.models import Rule, RiskRecord, Severity


class C1ContainerRootRule(Rule):
    @property
    def category(self) -> str:
        return "C-1"

    @property
    def name(self) -> str:
        return "コンテナがrootで実行される"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        for dockerfile in repo_path.rglob("Dockerfile*"):
            has_user = False
            try:
                with open(dockerfile, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip().upper().startswith("USER "):
                            has_user = True
                            break
                if not has_user:
                    risks.append(
                        RiskRecord(
                            category=self.category,
                            name=self.name,
                            severity=Severity.HIGH,
                            description="Dockerfile内でUSER命令が指定されておらず、コンテナがroot権限で実行される可能性があります。",
                            target_file=str(dockerfile.relative_to(repo_path)),
                            evidence="USER命令の欠如",
                        )
                    )
            except Exception:
                pass
        return risks


class C2SensitiveFileRule(Rule):
    @property
    def category(self) -> str:
        return "C-2"

    @property
    def name(self) -> str:
        return "機密情報ファイルの含有"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        # .git フォルダなどは無視する (.rglob は .で始まる隠しディレクトリも検索する)
        sensitive_patterns = [".env*", "*.pem", "*.key", "*_rsa"]

        for pattern in sensitive_patterns:
            for file in repo_path.rglob(pattern):
                if ".git" in file.parts:
                    continue
                # .env.example などのよくあるテンプレートファイルは除外
                if file.name.endswith(".example") or file.name.endswith(".template"):
                    continue

                risks.append(
                    RiskRecord(
                        category=self.category,
                        name=self.name,
                        severity=Severity.CRITICAL,
                        description=f"機密情報が含まれる可能性のあるファイル '{file.name}' がリポジトリ内に存在します。",
                        target_file=str(file.relative_to(repo_path)),
                        evidence=f"ファイル名: {file.name}",
                    )
                )
        return risks


class C3ExposedBindRule(Rule):
    @property
    def category(self) -> str:
        return "C-3"

    @property
    def name(self) -> str:
        return "アプリが0.0.0.0で待ち受け"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []

        target_files = []
        target_files.extend(repo_path.rglob("*.py"))
        target_files.extend(repo_path.rglob("*.js"))
        target_files.extend(repo_path.rglob("Dockerfile*"))
        target_files.extend(repo_path.rglob("docker-compose*"))
        target_files.extend(repo_path.rglob("*.yml"))
        target_files.extend(repo_path.rglob("*.yaml"))

        for file in target_files:
            if ".git" in file.parts:
                continue
            try:
                # Pythonファイルの特別なAST解析
                if file.suffix == ".py":
                    import ast

                    try:
                        with open(file, "r", encoding="utf-8") as f:
                            source = f.read()
                        tree = ast.parse(source)

                        for node in ast.walk(tree):
                            # キーワード引数での指定 (host="0.0.0.0") を探す
                            if isinstance(node, ast.Call):
                                for kw in node.keywords:
                                    if (
                                        kw.arg in ["host", "bind"]
                                        and isinstance(kw.value, ast.Constant)
                                        and kw.value.value == "0.0.0.0"
                                    ):
                                        risks.append(
                                            RiskRecord(
                                                category=self.category,
                                                name=self.name,
                                                severity=Severity.MEDIUM,
                                                description="AST解析: リバースプロキシ等なしで明示的に0.0.0.0でバインドしている可能性があります。",
                                                target_file=str(
                                                    file.relative_to(repo_path)
                                                ),
                                                line_number=node.lineno,
                                                evidence=f"{kw.arg}='0.0.0.0'",
                                            )
                                        )

                            # 辞書での設定 ({"host": "0.0.0.0"}) を探す
                            elif isinstance(node, ast.Dict):
                                for k, v in zip(node.keys, node.values):
                                    if isinstance(k, ast.Constant) and k.value in [
                                        "host",
                                        "bind",
                                        "HOST",
                                        "BIND",
                                    ]:
                                        if (
                                            isinstance(v, ast.Constant)
                                            and v.value == "0.0.0.0"
                                        ):
                                            risks.append(
                                                RiskRecord(
                                                    category=self.category,
                                                    name=self.name,
                                                    severity=Severity.MEDIUM,
                                                    description="AST解析: 辞書設定で明示的に0.0.0.0でバインドしている可能性があります。",
                                                    target_file=str(
                                                        file.relative_to(repo_path)
                                                    ),
                                                    line_number=node.lineno,
                                                    evidence=f"'{k.value}': '0.0.0.0'",
                                                )
                                            )

                            # 変数への代入 (HOST = "0.0.0.0") を探す
                            elif isinstance(node, ast.Assign):
                                if (
                                    isinstance(node.value, ast.Constant)
                                    and node.value.value == "0.0.0.0"
                                ):
                                    for target in node.targets:
                                        if isinstance(target, ast.Name):
                                            risks.append(
                                                RiskRecord(
                                                    category=self.category,
                                                    name=self.name,
                                                    severity=Severity.MEDIUM,
                                                    description="AST解析: 変数への代入で明示的に0.0.0.0でバインドしている可能性があります。",
                                                    target_file=str(
                                                        file.relative_to(repo_path)
                                                    ),
                                                    line_number=node.lineno,
                                                    evidence=f"{target.id} = '0.0.0.0'",
                                                )
                                            )
                    except Exception:
                        pass  # 構文エラー等は無視

                    continue  # Pythonファイルの場合は行ベースの単語検索はスキップして次へ

                # JS/TSファイルのコンテキスト考慮の疑似AST解析
                elif file.suffix in [".js", ".jsx", ".ts", ".tsx"]:
                    from ..utils.js_parser import check_0000_binding_in_js

                    suspicious_lines = check_0000_binding_in_js(file)
                    for ln in suspicious_lines:
                        with open(file, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                            evidence = lines[ln - 1].strip() if ln <= len(lines) else ""
                        risks.append(
                            RiskRecord(
                                category=self.category,
                                name=self.name,
                                severity=Severity.MEDIUM,
                                description="AST解析(疑似): リバースプロキシ等なしで明示的に0.0.0.0でバインドしている可能性があります。",
                                target_file=str(file.relative_to(repo_path)),
                                line_number=ln,
                                evidence=evidence,
                            )
                        )

                    continue  # JS/TSファイルの場合は行ベースの単語検索はスキップして次へ

                # Python/JS以外のファイルは従来通りテキストベースの解析
                with open(file, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        if "0.0.0.0" in line:
                            risks.append(
                                RiskRecord(
                                    category=self.category,
                                    name=self.name,
                                    severity=Severity.MEDIUM,
                                    description="リバースプロキシ等なしで明示的に0.0.0.0でバインドしている可能性があります。",
                                    target_file=str(file.relative_to(repo_path)),
                                    line_number=i,
                                    evidence=line.strip(),
                                )
                            )
            except Exception:
                pass
        return risks


class C4HighEntropySecretRule(Rule):
    @property
    def category(self) -> str:
        return "C-4"

    @property
    def name(self) -> str:
        return "ハードコードされた機密情報の疑い"

    def _calculate_shannon_entropy(self, data: str) -> float:
        """文字列のシャノンエントロピーを計算する"""
        import math
        from collections import Counter

        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        occurrences = Counter(data)

        for count in occurrences.values():
            p_x = float(count) / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    def _is_placeholder_value(self, literal: str) -> bool:
        lower = literal.lower()
        placeholders = [
            "example",
            "sample",
            "dummy",
            "test",
            "changeme",
            "localhost",
            "your_",
            "replace_me",
        ]
        return any(ph in lower for ph in placeholders)

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []

        # よくあるシークレットパターンの正規表現
        patterns = {
            "AWS Access Key ID": re.compile(
                r"(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
            ),
            "AWS Secret Access Key": re.compile(
                r"(?i)aws_secret_?(access)?_?key\s*={1,2}\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
            ),
            "GitHub Token": re.compile(r"(?i)gh[pousr]_[A-Za-z0-9_]{36}"),
            "Slack Token": re.compile(r"(?i)xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        }

        # 誤検知を下げるため、より厳格な閾値を利用する
        # 典型的には「24文字以上のランダムに見える文字列」をエントロピーで評価する
        entropy_threshold = 4.8
        min_secret_len = 24
        max_file_size = 1024 * 1024  # 1MB以上のファイルはスキップ

        # スキャン対象外とする拡張子やディレクトリ
        exclude_dirs = {".git", "node_modules", "venv", "__pycache__", "dist", "build"}
        exclude_exts = {
            ".jpg",
            ".png",
            ".gif",
            ".pdf",
            ".zip",
            ".tar",
            ".gz",
            ".pyc",
            ".bin",
            ".exe",
            ".dll",
            ".so",
            ".min.js",
            ".min.css",
        }

        # スキャン対象をコード・設定ファイル中心に限定して誤検知を抑制
        allowed_exts = {
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".json",
            ".yaml",
            ".yml",
            ".toml",
            ".ini",
            ".cfg",
            ".conf",
            ".env",
            ".sh",
            ".bash",
            ".txt",
        }
        allowed_names = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}

        # 行単位での「シークレット割り当て」の可能性を示す簡易正規表現 (1次フィルタ)
        assignment_pattern = re.compile(
            r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|private[_-]?key|auth|bearer)\b\s*[:=]"
        )
        string_literal_pattern = re.compile(r"['\"`]([a-zA-Z0-9+/=_-]{20,})['\"`]")

        for file in repo_path.rglob("*"):
            if not file.is_file():
                continue
            if any(ex in file.parts for ex in exclude_dirs):
                continue
            if file.suffix.lower() in exclude_exts:
                continue
            if (
                file.suffix.lower() not in allowed_exts
                and file.name not in allowed_names
            ):
                continue

            try:
                # ファイルサイズの事前チェック
                if file.stat().st_size > max_file_size:
                    continue

                # バイナリファイルの簡易検知 (先頭1024バイトにNull文字が含まれるか)
                with open(file, "rb") as f:
                    chunk = f.read(1024)
                    if b"\0" in chunk:
                        continue  # バイナリとしてスキップ

                with open(file, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        line_stripped = line.strip()
                        if not line_stripped:
                            continue

                        # 1. 正規表現による既知のパターンマッチ
                        matched_known = False
                        for secret_type, pat in patterns.items():
                            match = pat.search(line_stripped)
                            if match:
                                risks.append(
                                    RiskRecord(
                                        category=self.category,
                                        name=self.name,
                                        severity=Severity.CRITICAL,
                                        description=f"ハードコードされた {secret_type} が見つかりました。",
                                        target_file=str(file.relative_to(repo_path)),
                                        line_number=i,
                                        evidence=match.group(0)[:10]
                                        + "...",  # 一部だけ表示
                                    )
                                )
                                matched_known = True

                        if matched_known:
                            continue  # すでに検知済みの行はエントロピー判定をスキップ

                        # 2. シャノンエントロピーによる未知のクレデンシャル検知
                        # パフォーマンス向上のため、まずは「怪しい代入や単語」があるかを高速チェック
                        if assignment_pattern.search(line_stripped):
                            string_literals = string_literal_pattern.findall(
                                line_stripped
                            )
                            for literal in string_literals:
                                if len(literal) >= min_secret_len:
                                    if self._is_placeholder_value(literal):
                                        continue

                                    # 英数字のみの長文（例: ドキュメント断片）誤検知を抑制する
                                    has_digit_or_symbol = any(
                                        c.isdigit() for c in literal
                                    ) or any(c in "/+=_-" for c in literal)
                                    if not has_digit_or_symbol:
                                        continue

                                    ent = self._calculate_shannon_entropy(literal)
                                    if ent > entropy_threshold:
                                        risks.append(
                                            RiskRecord(
                                                category=self.category,
                                                name=self.name,
                                                severity=Severity.HIGH,
                                                description=f"エントロピーが非常に高い ({ent:.2f}) 文字列が存在します。パスワードやAPIトークンの可能性があります。",
                                                target_file=str(
                                                    file.relative_to(repo_path)
                                                ),
                                                line_number=i,
                                                evidence=literal[:10]
                                                + "...",  # 一部だけ表示
                                            )
                                        )

            except (UnicodeDecodeError, OSError):
                continue

        return risks
