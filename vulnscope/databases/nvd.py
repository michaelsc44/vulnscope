import asyncio
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import httpx

from vulnscope.databases.cache import CacheDB
from vulnscope.databases.cpe_map import clean_version_for_cpe, get_cpe_mapping
from vulnscope.inventory.os_info import OSInfo
from vulnscope.models import InstalledPackage, Severity, Vulnerability

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Only surface OS/kernel CVEs from the last 2 years to avoid ancient noise
OS_CVE_LOOKBACK_DAYS = 730


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
        cpes.append(f"cpe:2.3:o:{vendor}:{product}:{os_info.version}:*:*:*:*:*:*:*")

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


def _version_in_cpe_range(version: str, cpe_match: dict) -> bool:
    """Return True if version falls within the NVD CPE match's version range."""
    from vulnscope.matcher import _semver_compare as vcmp

    ver_start_incl = cpe_match.get("versionStartIncluding")
    ver_start_excl = cpe_match.get("versionStartExcluding")
    ver_end_incl = cpe_match.get("versionEndIncluding")
    ver_end_excl = cpe_match.get("versionEndExcluding")

    # Skip unbounded matches — without an upper bound we can't confirm vulnerability
    if not ver_end_incl and not ver_end_excl:
        return False

    if ver_start_incl and vcmp(version, ver_start_incl) < 0:
        return False
    if ver_start_excl and vcmp(version, ver_start_excl) <= 0:
        return False
    if ver_end_excl and vcmp(version, ver_end_excl) >= 0:
        return False
    if ver_end_incl and vcmp(version, ver_end_incl) > 0:
        return False

    return True


def _nvd_item_affects_version(
    item: dict, installed_version: str, vendor: str, product: str
) -> tuple[bool, str | None]:
    """Check that this CVE's CPE configuration actually covers our installed version.

    Returns (is_affected, fixed_version) where fixed_version is the versionEndExcluding
    value from the matching CPE range (i.e., the first version that is NOT vulnerable).
    """
    cve = item.get("cve", {})
    bare_version = clean_version_for_cpe(installed_version, "")

    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                criteria = cpe_match.get("criteria", "")
                if f":{vendor}:{product}:" not in criteria:
                    continue
                if _version_in_cpe_range(bare_version, cpe_match):
                    fixed = cpe_match.get("versionEndExcluding") or cpe_match.get("versionEndIncluding")
                    return True, fixed
    return False, None


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
        title=desc[:120] if desc else cve_id,
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
        # Without an API key: 5 req/30s; with key: 50/30s
        self._semaphore = asyncio.Semaphore(5 if not api_key else 50)

    def _headers(self) -> dict:
        if self.api_key:
            return {"apiKey": self.api_key}
        return {}

    async def _get(self, params: dict) -> dict | None:
        async with self._semaphore:
            await asyncio.sleep(0.5)
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.get(NVD_BASE_URL, params=params, headers=self._headers())
                    resp.raise_for_status()
                    return resp.json()
            except httpx.HTTPError:
                return None

    async def get_cve(self, cve_id: str, no_cache: bool = False) -> dict | None:
        if self.cache and not no_cache:
            cached = self.cache.get_nvd(cve_id)
            if cached is not None:
                return cached

        data = await self._get({"cveId": cve_id})
        if data and self.cache and not no_cache:
            self.cache.set_nvd(cve_id, data)
        return data

    async def query_os_cves(
        self,
        os_info: OSInfo,
        os_package: InstalledPackage,
        no_cache: bool = False,
        progress_cb: Callable[[int, int], None] | None = None,
    ) -> list[Vulnerability]:
        """Query NVD for OS/kernel CVEs, limited to recent publications."""
        cpes = _build_cpe_for_os(os_info)
        vulnerabilities: list[Vulnerability] = []

        # Only look at CVEs published in the last OS_CVE_LOOKBACK_DAYS days
        cutoff = datetime.now(timezone.utc) - timedelta(days=OS_CVE_LOOKBACK_DAYS)
        pub_start = cutoff.strftime("%Y-%m-%dT00:00:00.000")

        for i, cpe in enumerate(cpes):
            data = await self._get({
                "cpeName": cpe,
                "resultsPerPage": 50,
                "pubStartDate": pub_start,
            })
            if data:
                for item in data.get("vulnerabilities", []):
                    vuln = _nvd_item_to_vuln(item, os_package)
                    vulnerabilities.append(vuln)
            if progress_cb:
                progress_cb(i + 1, len(cpes))

        return vulnerabilities

    async def query_app_cves(
        self,
        packages: list[InstalledPackage],
        no_cache: bool = False,
        progress_cb: Callable[[int, int], None] | None = None,
    ) -> list[Vulnerability]:
        """Query NVD CPE database for vendor-installed applications (Chrome, Firefox, etc.).

        Uses CPE version range matching to confirm the installed version is actually
        in the vulnerable range — avoids the wildcard false positives that raw CPE
        queries produce.
        """
        # Build (package, vendor, product, bare_version) tuples for packages we have CPE data for
        targets: list[tuple[InstalledPackage, str, str, str]] = []
        for pkg in packages:
            mapping = get_cpe_mapping(pkg.name.lower())
            if mapping:
                vendor, product = mapping
                bare_ver = clean_version_for_cpe(pkg.version, pkg.ecosystem)
                targets.append((pkg, vendor, product, bare_ver))

        if not targets:
            return []

        vulnerabilities: list[Vulnerability] = []
        total = len(targets)

        for idx, (pkg, vendor, product, bare_ver) in enumerate(targets):
            cpe = f"cpe:2.3:a:{vendor}:{product}:{bare_ver}:*:*:*:*:*:*:*"

            # Check cache using CPE string as key
            cache_key = f"cpe:{cpe}"
            cached_data = None
            if self.cache and not no_cache:
                cached_data = self.cache.get_nvd(cache_key)

            if cached_data is None:
                data = await self._get({"cpeName": cpe, "resultsPerPage": 50})
                if data and self.cache and not no_cache:
                    self.cache.set_nvd(cache_key, data)
            else:
                data = cached_data

            if data:
                for item in data.get("vulnerabilities", []):
                    # Confirm this version is actually in the vulnerable range
                    affected, fixed_ver = _nvd_item_affects_version(item, bare_ver, vendor, product)
                    if affected:
                        vuln = _nvd_item_to_vuln(item, pkg)
                        if fixed_ver:
                            # Replace the stub vuln with one that has fixed_version set
                            from dataclasses import replace
                            vuln = replace(vuln, fixed_version=fixed_ver)
                        vulnerabilities.append(vuln)

            if progress_cb:
                progress_cb(idx + 1, total)

        return vulnerabilities

    async def enrich_vulnerabilities(
        self,
        vulnerabilities: list[Vulnerability],
        no_cache: bool = False,
    ) -> list[Vulnerability]:
        """Fetch NVD detail for CRITICAL/HIGH/UNKNOWN vulns to get accurate CVSS vectors.

        Deduplicates CVE IDs so each unique CVE is fetched only once, even when
        many packages share the same CVE (common with deb/distro advisories).
        """
        candidates = [
            v
            for v in vulnerabilities
            if v.severity in (Severity.CRITICAL, Severity.HIGH, Severity.UNKNOWN)
            and v.cve_id.startswith("CVE-")
            and v.source != "nvd"
        ]
        if not candidates:
            return vulnerabilities

        # Deduplicate: only fetch each unique CVE ID once
        unique_cve_ids = list({v.cve_id for v in candidates})

        # Fetch unique CVEs sequentially in small batches to respect rate limits
        enriched_map: dict[str, dict] = {}
        batch_size = 5 if not self.api_key else 40
        for i in range(0, len(unique_cve_ids), batch_size):
            batch = unique_cve_ids[i : i + batch_size]
            tasks = [self.get_cve(cve_id, no_cache=no_cache) for cve_id in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for cve_id, result in zip(batch, results):
                if isinstance(result, dict) and result:
                    items = result.get("vulnerabilities", [])
                    if items:
                        enriched_map[cve_id] = items[0]

            # Rate-limit pause between batches
            if i + batch_size < len(unique_cve_ids):
                await asyncio.sleep(6.0 if not self.api_key else 0.6)

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
