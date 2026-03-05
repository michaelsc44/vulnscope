import asyncio
from collections.abc import Callable

import httpx

from vulnscope.databases.cache import CacheDB
from vulnscope.inventory.os_info import OSInfo
from vulnscope.models import InstalledPackage, Severity, Vulnerability

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _build_cpe_for_os(os_info: OSInfo) -> list[str]:
    cpes = []
    vendor_map = {
        "ubuntu": ("canonical", "ubuntu_linux"),
        "debian": ("debian", "debian_linux"),
        "fedora": ("fedoraproject", "fedora"),
        "rhel": ("redhat", "enterprise_linux"),
        "centos": ("centos", "centos"),
        "alpine": ("alpinelinux", "alpine_linux"),
        "arch": ("archlinux", "arch_linux"),
    }
    if os_info.id in vendor_map:
        vendor, product = vendor_map[os_info.id]
        version = os_info.version
        cpes.append(f"cpe:2.3:o:{vendor}:{product}:{version}:*:*:*:*:*:*:*")

    kernel = os_info.kernel_version.split("-")[0]
    cpes.append(f"cpe:2.3:o:linux:linux_kernel:{kernel}:*:*:*:*:*:*:*")
    return cpes


def _parse_nvd_severity(metrics: dict) -> tuple[Severity, float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        for entry in entries:
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            vector = data.get("vectorString")
            severity_str = data.get("baseSeverity", "").upper()
            sev_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            sev = sev_map.get(severity_str, Severity.UNKNOWN)
            return sev, score, vector
    return Severity.UNKNOWN, None, None


def _nvd_item_to_vuln(item: dict, package: InstalledPackage) -> Vulnerability:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    metrics = cve.get("metrics", {})
    severity, score, vector = _parse_nvd_severity(metrics)

    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for desc_item in w.get("description", []):
            val = desc_item.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
    published = cve.get("published")

    return Vulnerability(
        cve_id=cve_id,
        aliases=[],
        title=desc[:100] if desc else cve_id,
        description=desc,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cwe_ids=cwe_ids,
        affected_package=package,
        fixed_version=None,
        is_known_exploited=False,
        kev_due_date=None,
        references=refs,
        published_date=published,
        source="nvd",
    )


class NvdClient:
    def __init__(self, api_key: str | None = None, cache: CacheDB | None = None):
        self.api_key = api_key
        self.cache = cache
        self._semaphore = asyncio.Semaphore(5 if not api_key else 50)
        self._last_request = 0.0

    def _headers(self) -> dict:
        if self.api_key:
            return {"apiKey": self.api_key}
        return {}

    async def get_cve(self, cve_id: str, no_cache: bool = False) -> dict | None:
        if self.cache and not no_cache:
            cached = self.cache.get_nvd(cve_id)
            if cached is not None:
                return cached

        async with self._semaphore:
            await asyncio.sleep(0.1)
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.get(
                        NVD_BASE_URL,
                        params={"cveId": cve_id},
                        headers=self._headers(),
                    )
                    resp.raise_for_status()
                    data = resp.json()
            except httpx.HTTPError:
                return None

        if self.cache and not no_cache:
            self.cache.set_nvd(cve_id, data)
        return data

    async def query_os_cves(
        self,
        os_info: OSInfo,
        os_package: InstalledPackage,
        no_cache: bool = False,
        progress_cb: Callable[[int, int], None] | None = None,
    ) -> list[Vulnerability]:
        cpes = _build_cpe_for_os(os_info)
        vulnerabilities: list[Vulnerability] = []

        for i, cpe in enumerate(cpes):
            async with self._semaphore:
                await asyncio.sleep(0.2)
                try:
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        resp = await client.get(
                            NVD_BASE_URL,
                            params={"cpeName": cpe, "resultsPerPage": 20},
                            headers=self._headers(),
                        )
                        resp.raise_for_status()
                        data = resp.json()
                except httpx.HTTPError:
                    continue

            for item in data.get("vulnerabilities", []):
                vuln = _nvd_item_to_vuln(item, os_package)
                vulnerabilities.append(vuln)

            if progress_cb:
                progress_cb(i + 1, len(cpes))

        return vulnerabilities

    async def enrich_vulnerabilities(
        self,
        vulnerabilities: list[Vulnerability],
        no_cache: bool = False,
    ) -> list[Vulnerability]:
        """Fetch NVD detail for CRITICAL/HIGH vulns to get CVSS vectors."""
        high_vulns = [
            v for v in vulnerabilities if v.severity in (Severity.CRITICAL, Severity.HIGH) and v.cve_id.startswith("CVE-")
        ]
        if not high_vulns:
            return vulnerabilities

        tasks = [self.get_cve(v.cve_id, no_cache=no_cache) for v in high_vulns]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        enriched_map: dict[str, dict] = {}
        for vuln, result in zip(high_vulns, results):
            if isinstance(result, dict) and result:
                items = result.get("vulnerabilities", [])
                if items:
                    enriched_map[vuln.cve_id] = items[0]

        updated = []
        for v in vulnerabilities:
            if v.cve_id in enriched_map:
                item = enriched_map[v.cve_id]
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                sev, score, vector = _parse_nvd_severity(metrics)

                weaknesses = cve.get("weaknesses", [])
                cwe_ids = []
                for w in weaknesses:
                    for d in w.get("description", []):
                        val = d.get("value", "")
                        if val.startswith("CWE-"):
                            cwe_ids.append(val)

                updated.append(
                    Vulnerability(
                        cve_id=v.cve_id,
                        aliases=v.aliases,
                        title=v.title,
                        description=v.description,
                        severity=sev if sev != Severity.UNKNOWN else v.severity,
                        cvss_score=score if score is not None else v.cvss_score,
                        cvss_vector=vector or v.cvss_vector,
                        cwe_ids=cwe_ids or v.cwe_ids,
                        affected_package=v.affected_package,
                        fixed_version=v.fixed_version,
                        is_known_exploited=v.is_known_exploited,
                        kev_due_date=v.kev_due_date,
                        references=v.references,
                        published_date=v.published_date,
                        source=v.source,
                    )
                )
            else:
                updated.append(v)

        return updated
