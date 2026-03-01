import json
from pathlib import Path
from typing import Dict, List, Tuple

def parse_requirements_txt(filepath: Path) -> List[Tuple[str, str, int]]:
    """
    requirements.txtをパースして、(パッケージ名, バージョン指定, 行番号)のリストを返す。
    簡単なパースのみを行う。
    """
    deps = []
    if not filepath.exists():
        return deps
        
    with open(filepath, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # == / >= / <= などの分割による簡易抽出
            # 実際にはパッケージングの仕様に準拠すべきだが、ここでは簡易的に実装
            if "==" in line:
                parts = line.split("==")
                deps.append((parts[0].strip(), f"=={parts[1].strip()}", i))
            elif ">=" in line:
                parts = line.split(">=")
                deps.append((parts[0].strip(), f">={parts[1].strip()}", i))
            elif "<=" in line:
                parts = line.split("<=")
                deps.append((parts[0].strip(), f"<={parts[1].strip()}", i))
            else:
                deps.append((line, "", i)) # バージョン指定なし
    return deps

def parse_package_json(filepath: Path) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    package.jsonを解析して、dependenciesとdevDependenciesの辞書を返す。
    """
    if not filepath.exists():
        return {}, {}
        
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            return deps, dev_deps
    except BaseException:
        return {}, {}

def parse_package_lock_json(filepath: Path) -> Dict[str, str]:
    """
    package-lock.json（v2/v3）を解析して、推移的依存関係を含む
    平坦化された (パッケージ名: バージョン) の辞書を返す。
    """
    if not filepath.exists():
        return {}
        
    resolved_deps = {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            
            # lockfile v2/v3 (npm v7+) の場合
            packages = data.get("packages", {})
            if packages:
                for pkg_path, pkg_info in packages.items():
                    # ルートパッケージ ("") は除外
                    if not pkg_path:
                        continue
                    
                    # 例: "node_modules/foo/node_modules/bar" -> "bar"
                    pkg_name = pkg_path.split("node_modules/")[-1]
                    version = pkg_info.get("version")
                    if pkg_name and version:
                        # 複数箇所で同じ名前の別バージョンが定義されている場合、
                        # リスク判定目的のためリスト化などの高度な処理が必要だが、
                        # 今回は簡易的に最新に上書き（もしくは最初に見つけたもの）とする。
                        if pkg_name not in resolved_deps:
                            resolved_deps[pkg_name] = version
                            
            else:
                # lockfile v1 (npm v6以前) の場合
                dependencies = data.get("dependencies", {})
                
                def traverse(deps_dict):
                    for name, info in deps_dict.items():
                        ver = info.get("version")
                        if ver and name not in resolved_deps:
                            resolved_deps[name] = ver
                        if "dependencies" in info:
                            traverse(info["dependencies"])
                            
                traverse(dependencies)
                
    except BaseException:
        pass
        
    return resolved_deps

def parse_poetry_lock(filepath: Path) -> Dict[str, str]:
    """
    poetry.lock (TOML format) を解析して、推移的依存関係を含む
    平坦化された (パッケージ名: バージョン) の辞書を返す。
    """
    if not filepath.exists():
        return {}
        
    resolved_deps = {}
    try:
        import tomli # Using tomli for robust toml parsing, or fallback to simple regex if not available
    except ImportError:
        tomli = None

    if tomli:
        try:
            with open(filepath, "rb") as f:
                data = tomli.load(f)
                packages = data.get("package", [])
                for pkg in packages:
                    name = pkg.get("name")
                    version = pkg.get("version")
                    if name and version:
                        resolved_deps[name] = version
            return resolved_deps
        except Exception:
            pass
            
    # Fallback: simple text parsing for poetry.lock
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            current_name = None
            for line in f:
                line = line.strip()
                if line == "[[package]]":
                    current_name = None
                elif line.startswith('name = '):
                    current_name = line.split('=')[1].strip().strip('"').strip("'")
                elif line.startswith('version = ') and current_name:
                    version = line.split('=')[1].strip().strip('"').strip("'")
                    resolved_deps[current_name] = version
                    current_name = None
    except Exception:
        pass
        
    return resolved_deps

def parse_go_mod(filepath: Path) -> Dict[str, str]:
    """
    go.sumを解析して、推移的依存関係を含む
    平坦化された (モジュールパス: バージョン) の辞書を返す。
    go.sumが存在しない場合はgo.modから簡易抽出する。
    """
    if not filepath.exists():
        return {}
        
    resolved_deps = {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                
                parts = line.split()
                # go.sum format: <module_path> <version>[/go.mod] <hash>
                if len(parts) >= 2:
                    module_path = parts[0]
                    version = parts[1]
                    
                    # /go.mod is appended for the pseudo-version hash lines
                    if version.endswith("/go.mod"):
                        version = version[:-7]
                    
                    # Store the highest version (basic string comparison for simplicity, though semver would be better)
                    if module_path not in resolved_deps or version > resolved_deps[module_path]:
                        resolved_deps[module_path] = version
                        
    except Exception:
        pass
        
    return resolved_deps

def parse_cargo_lock(filepath: Path) -> Dict[str, str]:
    """
    Cargo.lock (TOML format) を解析して、推移的依存関係を含む
    平坦化された (パッケージ名: バージョン) の辞書を返す。
    """
    if not filepath.exists():
        return {}
        
    resolved_deps = {}
    try:
        import tomli
    except ImportError:
        tomli = None

    if tomli:
        try:
            with open(filepath, "rb") as f:
                data = tomli.load(f)
                packages = data.get("package", [])
                for pkg in packages:
                    name = pkg.get("name")
                    version = pkg.get("version")
                    if name and version:
                        resolved_deps[name] = version
            return resolved_deps
        except Exception:
            pass
            
    # Fallback: simple text parsing for Cargo.lock
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            current_name = None
            for line in f:
                line = line.strip()
                if line == "[[package]]":
                    current_name = None
                elif line.startswith('name = '):
                    current_name = line.split('=')[1].strip().strip('"').strip("'")
                elif line.startswith('version = ') and current_name:
                    version = line.split('=')[1].strip().strip('"').strip("'")
                    resolved_deps[current_name] = version
                    current_name = None
    except Exception:
        pass
        
    return resolved_deps

