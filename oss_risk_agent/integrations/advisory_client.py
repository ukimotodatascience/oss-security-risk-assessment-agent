"""Advisory data source client skeleton."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


@dataclass(slots=True)
class VulnerabilitySignal:
    cve_id: str
    cvss: float | None = None
    epss_percentile: float | None = None
    kev_flag: bool = False
    exploit_available: bool = False
    source: str | None = None


class AdvisoryClient:
    """Adapter over KEV / GHSA / OSV / NVD sources."""

    def __init__(
        self,
        signals_by_package: (
            Mapping[str, Mapping[str, list[VulnerabilitySignal]]] | None
        ) = None,
        github_token: str | None = None,
        nvd_api_key: str | None = None,
        timeout_sec: float = 10.0,
    ) -> None:
        """Initialize advisory client.

        Args:
            signals_by_package:
                Optional in-memory vulnerability index for local testing.
                Shape:
                {
                  "package-name": {
                    "1.2.3": [VulnerabilitySignal(...)],
                    "*": [VulnerabilitySignal(...)]
                  }
                }
        """
        self._signals_by_package = signals_by_package or {}
        self._github_token = (
            github_token or os.getenv("GITHUB_TOKEN") or "DUMMY_GITHUB_TOKEN"
        )
        self._nvd_api_key = (
            nvd_api_key or os.getenv("NVD_API_KEY") or "DUMMY_NVD_API_KEY"
        )
        self._timeout_sec = timeout_sec

    def lookup(
        self,
        package_name: str,
        version: str,
        ecosystem: str | None = None,
    ) -> list[VulnerabilitySignal]:
        """Return vulnerability signals for a dependency.

        Source priority:
        1) CISA KEV
        2) GitHub Advisory
        3) OSV
        4) NVD

        Lookup strategy:
        - local in-memory signals (for tests)
        - external API aggregation (best effort)
        - de-duplication by vulnerability id / alias
        """
        normalized_package = package_name.strip().lower()
        normalized_version = version.strip()
        if not normalized_package or not normalized_version:
            return []

        local: list[VulnerabilitySignal] = []
        if self._signals_by_package:
            # ローカル辞書が設定されている場合のみ参照（主にテスト用途）
            local = self._lookup_local(normalized_package, normalized_version)
        external = self._lookup_external(
            package_name=normalized_package,
            version=normalized_version,
            ecosystem=ecosystem,
        )

        merged = self._merge_signals(local + external)
        return merged

    def _lookup_local(
        self, package_name: str, version: str
    ) -> list[VulnerabilitySignal]:
        package_map = self._signals_by_package.get(package_name)
        if not package_map:
            return []
        if version in package_map:
            return list(package_map[version])
        if "*" in package_map:
            return list(package_map["*"])
        return []

    def _lookup_external(
        self,
        package_name: str,
        version: str,
        ecosystem: str | None,
    ) -> list[VulnerabilitySignal]:
        ecosystems = self._resolve_ecosystems(ecosystem)
        signals: list[VulnerabilitySignal] = []

        # 優先順どおりに追加（最後にmergeで統合）
        signals.extend(self._query_kev(package_name))
        signals.extend(self._query_github_advisory(package_name, version, ecosystems))
        signals.extend(self._query_osv(package_name, version, ecosystems))
        signals.extend(self._query_nvd(package_name))
        return signals

    @staticmethod
    def _resolve_ecosystems(ecosystem: str | None) -> list[str]:
        if ecosystem == "pypi":
            return ["PyPI"]
        if ecosystem == "npm":
            return ["npm"]
        # 未指定時はPyPI/NPMの両方を試す
        return ["PyPI", "npm"]

    def _query_osv(
        self,
        package_name: str,
        version: str,
        ecosystems: list[str],
    ) -> list[VulnerabilitySignal]:
        results: list[VulnerabilitySignal] = []
        for eco in ecosystems:
            payload = {
                "package": {"name": package_name, "ecosystem": eco},
                "version": version,
            }
            data = self._http_json(
                "POST",
                "https://api.osv.dev/v1/query",
                headers={"Content-Type": "application/json"},
                payload=payload,
            )
            vulns = data.get("vulns", []) if isinstance(data, dict) else []
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id") or "").strip()
                if not vuln_id:
                    continue
                aliases = vuln.get("aliases")
                cve = vuln_id
                if isinstance(aliases, list):
                    cve_alias = next(
                        (
                            str(a)
                            for a in aliases
                            if isinstance(a, str) and a.startswith("CVE-")
                        ),
                        None,
                    )
                    if cve_alias:
                        cve = cve_alias
                results.append(
                    VulnerabilitySignal(
                        cve_id=cve,
                        cvss=self._extract_cvss_from_osv(vuln),
                        source="osv",
                    )
                )
        return results

    def _query_github_advisory(
        self,
        package_name: str,
        version: str,
        ecosystems: list[str],
    ) -> list[VulnerabilitySignal]:
        results: list[VulnerabilitySignal] = []
        ecosystem_map = {"PyPI": "pip", "npm": "npm"}
        for eco in ecosystems:
            gh_eco = ecosystem_map.get(eco)
            if not gh_eco:
                continue

            query = urlencode(
                {"ecosystem": gh_eco, "affects": package_name, "per_page": "50"}
            )
            headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
            if self._github_token and self._github_token != "DUMMY_GITHUB_TOKEN":
                headers["Authorization"] = f"Bearer {self._github_token}"

            data = self._http_json(
                "GET",
                f"https://api.github.com/advisories?{query}",
                headers=headers,
            )
            if not isinstance(data, list):
                continue

            for item in data:
                if not isinstance(item, dict):
                    continue
                vuln_id = str(item.get("cve_id") or item.get("ghsa_id") or "").strip()
                if not vuln_id:
                    continue

                # GitHub APIのrange表現は多様なので、
                # ここではversion判定は将来強化前提で保守的に採用。
                if not self._github_advisory_may_affect_version(item, version):
                    continue

                results.append(
                    VulnerabilitySignal(
                        cve_id=vuln_id,
                        cvss=self._extract_cvss_from_ghsa(item),
                        source="ghsa",
                    )
                )
        return results

    @staticmethod
    def _github_advisory_may_affect_version(item: dict[str, Any], version: str) -> bool:
        vulnerabilities = item.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            return True
        for entry in vulnerabilities:
            if not isinstance(entry, dict):
                continue
            # 厳密なsemver/pep440評価は将来拡張。現段階では
            # patched_versions に現versionが含まれていれば除外する。
            patched = str(entry.get("patched_versions") or "")
            if version and version in patched:
                return False
        return True

    def _query_nvd(self, package_name: str) -> list[VulnerabilitySignal]:
        query = urlencode({"keywordSearch": package_name, "resultsPerPage": "20"})
        headers = {"apiKey": self._nvd_api_key} if self._nvd_api_key else {}
        data = self._http_json(
            "GET",
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}",
            headers=headers,
        )
        if not isinstance(data, dict):
            return []

        vulns = data.get("vulnerabilities", [])
        results: list[VulnerabilitySignal] = []
        if not isinstance(vulns, list):
            return results

        for entry in vulns:
            cve = entry.get("cve") if isinstance(entry, dict) else None
            if not isinstance(cve, dict):
                continue
            vuln_id = str(cve.get("id") or "").strip()
            if not vuln_id:
                continue
            results.append(
                VulnerabilitySignal(
                    cve_id=vuln_id,
                    cvss=self._extract_cvss_from_nvd(cve),
                    source="nvd",
                )
            )
        return results

    def _query_kev(self, package_name: str) -> list[VulnerabilitySignal]:
        data = self._http_json(
            "GET",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        )
        if not isinstance(data, dict):
            return []
        vulns = data.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            return []

        package_name = package_name.lower()
        results: list[VulnerabilitySignal] = []
        for item in vulns:
            if not isinstance(item, dict):
                continue
            vendor = str(item.get("vendorProject") or "").lower()
            product = str(item.get("product") or "").lower()
            if package_name not in vendor and package_name not in product:
                continue
            cve_id = str(item.get("cveID") or "").strip()
            if not cve_id:
                continue
            results.append(
                VulnerabilitySignal(
                    cve_id=cve_id,
                    kev_flag=True,
                    source="kev",
                )
            )
        return results

    def _http_json(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        body = None
        final_headers: dict[str, str] = {"User-Agent": "oss-risk-agent/0.1"}
        if headers:
            final_headers.update(headers)
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")

        request = Request(url=url, method=method, headers=final_headers, data=body)
        try:
            with urlopen(request, timeout=self._timeout_sec) as response:
                raw = response.read().decode("utf-8", errors="ignore")
                return json.loads(raw)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError):
            return {}

    @staticmethod
    def _extract_cvss_from_osv(vuln: dict[str, Any]) -> float | None:
        severity = vuln.get("severity")
        if isinstance(severity, list):
            for item in severity:
                if not isinstance(item, dict):
                    continue
                score = item.get("score")
                if isinstance(score, str):
                    # CVSS:3.1/AV:N/... は将来厳密パース可能。
                    # ここでは末尾数値を拾わず、欠損扱いにする。
                    continue
        return None

    @staticmethod
    def _extract_cvss_from_ghsa(item: dict[str, Any]) -> float | None:
        cvss = item.get("cvss")
        if isinstance(cvss, dict):
            score = cvss.get("score")
            if isinstance(score, (int, float)):
                return float(score)
        score = item.get("cvss_severity")
        if isinstance(score, (int, float)):
            return float(score)
        return None

    @staticmethod
    def _extract_cvss_from_nvd(cve: dict[str, Any]) -> float | None:
        metrics = cve.get("metrics")
        if not isinstance(metrics, dict):
            return None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key)
            if not isinstance(values, list) or not values:
                continue
            first = values[0]
            if not isinstance(first, dict):
                continue
            cvss_data = first.get("cvssData")
            if not isinstance(cvss_data, dict):
                continue
            score = cvss_data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
        return None

    @staticmethod
    def _merge_signals(signals: list[VulnerabilitySignal]) -> list[VulnerabilitySignal]:
        merged: dict[str, VulnerabilitySignal] = {}
        source_priority = {"kev": 4, "ghsa": 3, "osv": 2, "nvd": 1, None: 0}

        for signal in signals:
            key = signal.cve_id.strip().upper()
            if not key:
                continue
            current = merged.get(key)
            if current is None:
                merged[key] = signal
                continue

            # 優先ソースを保持しつつ、欠損値を補完
            current_priority = source_priority.get(current.source, 0)
            new_priority = source_priority.get(signal.source, 0)
            if new_priority > current_priority:
                winner = signal
                loser = current
            else:
                winner = current
                loser = signal

            merged[key] = VulnerabilitySignal(
                cve_id=winner.cve_id,
                cvss=winner.cvss if winner.cvss is not None else loser.cvss,
                epss_percentile=(
                    winner.epss_percentile
                    if winner.epss_percentile is not None
                    else loser.epss_percentile
                ),
                kev_flag=winner.kev_flag or loser.kev_flag,
                exploit_available=winner.exploit_available or loser.exploit_available,
                source=winner.source,
            )

        return list(merged.values())
