from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

from .parsers import (
    parse_cargo_lock,
    parse_go_mod,
    parse_package_json,
    parse_package_lock_json,
    parse_poetry_lock,
    parse_requirements_txt,
)


def collect_dependencies(repo_path: Path) -> List[Tuple[str, str, str, bool]]:
    """
    Return dependencies as tuples:
      (ecosystem, name, version_or_spec, is_transitive)
    """
    items: List[Tuple[str, str, str, bool]] = []

    req = repo_path / "requirements.txt"
    if req.exists():
        for name, spec, _ in parse_requirements_txt(req):
            items.append(("PyPI", name, spec or "", False))

    poetry_lock = repo_path / "poetry.lock"
    if poetry_lock.exists():
        for name, version in parse_poetry_lock(poetry_lock).items():
            items.append(("PyPI", name, version, True))

    package_json = repo_path / "package.json"
    if package_json.exists():
        deps, dev_deps = parse_package_json(package_json)
        for name, version in {**deps, **dev_deps}.items():
            items.append(("npm", name, version, False))

    package_lock = repo_path / "package-lock.json"
    if package_lock.exists():
        for name, version in parse_package_lock_json(package_lock).items():
            items.append(("npm", name, version, True))

    go_sum = repo_path / "go.sum"
    go_mod = repo_path / "go.mod"
    go_file = go_sum if go_sum.exists() else go_mod
    if go_file.exists():
        for name, version in parse_go_mod(go_file).items():
            items.append(("Go", name, version, True))

    cargo_lock = repo_path / "Cargo.lock"
    if cargo_lock.exists():
        for name, version in parse_cargo_lock(cargo_lock).items():
            items.append(("crates.io", name, version, True))

    # de-duplicate keeping first occurrence
    seen = set()
    deduped = []
    for entry in items:
        key = (entry[0], entry[1], entry[2], entry[3])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)

    return deduped


def has_unpinned_version(version_or_spec: str) -> bool:
    v = (version_or_spec or "").strip()
    if not v:
        return True

    if v.startswith("=="):
        return False

    # strict semver-ish number without operators
    if v.replace(".", "").replace("-", "").isalnum() and not any(
        c in v for c in ["^", "~", "*", ">", "<", "=", "x", "X", "|"]
    ):
        return False

    return True


def generate_cyclonedx_sbom(repo_path: Path, output_path: Path | None = None) -> Dict:
    components = []
    deps = collect_dependencies(repo_path)

    for ecosystem, name, version, is_transitive in deps:
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version.lstrip("=") if version else "",
                "purl": f"pkg:{ecosystem.lower()}/{name}",
                "properties": [
                    {"name": "oss_risk_agent:ecosystem", "value": ecosystem},
                    {
                        "name": "oss_risk_agent:is_transitive",
                        "value": str(is_transitive).lower(),
                    },
                ],
            }
        )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": repo_path.name,
            }
        },
        "components": components,
    }

    if output_path:
        output_path.write_text(
            json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    return sbom
