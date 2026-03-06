import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx

from vulnscope.databases.cache import CacheDB
from vulnscope.databases.cpe_map import clean_version_for_cpe, get_cpe_mapping
from vulnscope.databases.kev import _index_catalog, load_kev_catalog
from vulnscope.databases.nvd import (
    NVD_BASE_URL,
    NvdClient,
    _nvd_item_affects_version,
    _version_in_cpe_range,
)
from vulnscope.databases.osv import _get_cve_id, query_osv_batch
from vulnscope.models import InstalledPackage, Severity, Vulnerability

FIXTURES = Path(__file__).parent / "fixtures"


def make_package(name: str, version: str, ecosystem: str = "pypi") -> InstalledPackage:
    purl = f"pkg:{ecosystem}/{name}@{version}"
    return InstalledPackage(
        name=name, version=version, ecosystem=ecosystem, source="pip",
        arch=None, purl=purl,
    )


class TestCacheDB:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.sqlite"
        self.cache = CacheDB(db_path=self.db_path, ttl_hours=24)

    def test_osv_round_trip(self):
        data = {"vulns": [{"id": "CVE-2023-1234"}]}
        self.cache.set_osv("pkg:pypi/requests@2.31.0", data)
        result = self.cache.get_osv("pkg:pypi/requests@2.31.0")
        assert result == data

    def test_osv_miss_returns_none(self):
        result = self.cache.get_osv("pkg:pypi/nonexistent@0.0.1")
        assert result is None

    def test_nvd_round_trip(self):
        data = {"vulnerabilities": [{"cve": {"id": "CVE-2023-1234"}}]}
        self.cache.set_nvd("CVE-2023-1234", data)
        result = self.cache.get_nvd("CVE-2023-1234")
        assert result == data

    def test_kev_round_trip(self):
        data = {"vulnerabilities": [{"cveID": "CVE-2024-3094"}]}
        self.cache.set_kev(data)
        result = self.cache.get_kev()
        assert result == data

    def test_expired_cache_returns_none(self):
        cache = CacheDB(db_path=self.db_path, ttl_hours=0)
        data = {"vulns": []}
        cache.set_osv("pkg:pypi/test@1.0", data)
        result = cache.get_osv("pkg:pypi/test@1.0")
        assert result is None


class TestKevCatalog:
    def test_index_catalog(self):
        fixture = json.loads((FIXTURES / "kev_response.json").read_text())
        result = _index_catalog(fixture)
        assert "CVE-2024-3094" in result
        assert "CVE-2024-6387" in result
        assert result["CVE-2024-3094"]["product"] == "xz-utils"

    @pytest.mark.asyncio
    async def test_load_kev_uses_cache(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = CacheDB(db_path=Path(tmpdir) / "test.sqlite")
            fixture = json.loads((FIXTURES / "kev_response.json").read_text())
            cache.set_kev(fixture)

            result = await load_kev_catalog(cache=cache, no_cache=False)
            assert "CVE-2024-3094" in result

    @pytest.mark.asyncio
    async def test_load_kev_fetches_when_no_cache(self):
        fixture = json.loads((FIXTURES / "kev_response.json").read_text())
        with respx.mock:
            respx.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").mock(
                return_value=httpx.Response(200, json=fixture)
            )
            result = await load_kev_catalog(no_cache=True)
        assert "CVE-2024-3094" in result


class TestOsvBatchQuery:
    @pytest.mark.asyncio
    async def test_query_returns_vulnerabilities(self):
        fixture = json.loads((FIXTURES / "osv_response.json").read_text())
        pkg1 = make_package("requests", "2.30.0")
        pkg2 = make_package("certifi", "2023.7.22")

        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=fixture)
            )
            result = await query_osv_batch([pkg1, pkg2], no_cache=True)

        assert len(result) >= 1
        cve_ids = [v.cve_id for v in result]
        assert "CVE-2023-32681" in cve_ids

    @pytest.mark.asyncio
    async def test_query_empty_packages(self):
        result = await query_osv_batch([], no_cache=True)
        assert result == []

    @pytest.mark.asyncio
    async def test_network_error_returns_empty(self):
        pkg = make_package("requests", "2.30.0")
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await query_osv_batch([pkg], no_cache=True)
        assert result == []

    @pytest.mark.asyncio
    async def test_uses_cache(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = CacheDB(db_path=Path(tmpdir) / "test.sqlite")
            pkg = make_package("requests", "2.28.0")

            fixture = json.loads((FIXTURES / "osv_response.json").read_text())
            vulns = fixture["results"][0]["vulns"]
            cache.set_osv(pkg.purl, {"vulns": vulns})

            result = await query_osv_batch([pkg], cache=cache, no_cache=False)
            assert len(result) >= 1


def _make_vuln(cve_id: str, pkg_name: str, severity: Severity = Severity.UNKNOWN) -> Vulnerability:
    pkg = make_package(pkg_name, "1.0.0", "deb")
    return Vulnerability(
        cve_id=cve_id, aliases=[], title=cve_id, description="",
        severity=severity, cvss_score=None, cvss_vector=None, cwe_ids=[],
        affected_package=pkg, fixed_version=None, is_known_exploited=False,
        kev_due_date=None, references=[], published_date=None, source="osv",
    )


class TestNvdEnrichDedup:
    """Verify that enrich_vulnerabilities deduplicates CVE lookups."""

    @pytest.mark.asyncio
    async def test_deduplicates_cve_lookups(self):
        """When 5 vulns share 2 CVE IDs, only 2 API calls should be made."""
        vulns = [
            _make_vuln("CVE-2024-1111", "libssl3"),
            _make_vuln("CVE-2024-1111", "openssl"),
            _make_vuln("CVE-2024-1111", "libssl-dev"),
            _make_vuln("CVE-2024-2222", "curl"),
            _make_vuln("CVE-2024-2222", "libcurl4"),
        ]

        nvd_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "placeholder",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                            }
                        }]
                    },
                    "weaknesses": [],
                }
            }]
        }

        call_count = 0

        async def mock_get_cve(self, cve_id, no_cache=False):
            nonlocal call_count
            call_count += 1
            return nvd_response

        client = NvdClient()
        with patch.object(NvdClient, "get_cve", mock_get_cve):
            result = await client.enrich_vulnerabilities(vulns, no_cache=True)

        assert call_count == 2, f"Expected 2 API calls for 2 unique CVEs, got {call_count}"
        # All 5 vulns should be enriched with HIGH severity
        for v in result:
            assert v.severity == Severity.HIGH
            assert v.cvss_score == 7.5


class TestGetCveId:
    def test_extracts_cve_from_aliases(self):
        vuln = {"id": "GHSA-abcd-1234", "aliases": ["CVE-2023-12345"]}
        assert _get_cve_id(vuln) == "CVE-2023-12345"

    def test_ubuntu_prefix_extraction(self):
        vuln = {"id": "UBUNTU-CVE-2022-40735", "aliases": []}
        assert _get_cve_id(vuln) == "CVE-2022-40735"

    def test_debian_prefix_extraction(self):
        vuln = {"id": "DEBIAN-CVE-2023-50387", "aliases": []}
        assert _get_cve_id(vuln) == "CVE-2023-50387"

    def test_alpine_prefix_extraction(self):
        vuln = {"id": "ALPINE-CVE-2024-1234", "aliases": []}
        assert _get_cve_id(vuln) == "CVE-2024-1234"

    def test_aliases_preferred_over_distro_prefix(self):
        vuln = {"id": "UBUNTU-CVE-2022-40735", "aliases": ["CVE-2022-40735"]}
        assert _get_cve_id(vuln) == "CVE-2022-40735"

    def test_falls_back_to_osv_id(self):
        vuln = {"id": "PYSEC-2023-100", "aliases": []}
        assert _get_cve_id(vuln) == "PYSEC-2023-100"

    def test_no_aliases_key(self):
        vuln = {"id": "GHSA-xxxx-yyyy"}
        assert _get_cve_id(vuln) == "GHSA-xxxx-yyyy"

    def test_empty_vuln(self):
        assert _get_cve_id({}) == ""


class TestCpeMapping:
    def test_known_package_lookup(self):
        assert get_cpe_mapping("google-chrome-stable") == ("google", "chrome")
        assert get_cpe_mapping("firefox") == ("mozilla", "firefox")
        assert get_cpe_mapping("code") == ("microsoft", "visual_studio_code")

    def test_case_insensitive(self):
        assert get_cpe_mapping("Google-Chrome-Stable") == ("google", "chrome")
        assert get_cpe_mapping("FIREFOX") == ("mozilla", "firefox")

    def test_unknown_package_returns_none(self):
        assert get_cpe_mapping("some-unknown-package") is None

    def test_clean_version_deb_suffix(self):
        assert clean_version_for_cpe("144.0.7559.132-1", "deb") == "144.0.7559.132"

    def test_clean_version_snap_suffix(self):
        assert clean_version_for_cpe("148.0-1", "snap") == "148.0"

    def test_clean_version_no_suffix(self):
        assert clean_version_for_cpe("7.95", "snap") == "7.95"

    def test_clean_version_other_ecosystem_unchanged(self):
        assert clean_version_for_cpe("1.2.3-beta1", "pypi") == "1.2.3-beta1"


class TestVersionInCpeRange:
    def test_within_range_exclusive_end(self):
        cpe_match = {"versionStartIncluding": "1.0.0", "versionEndExcluding": "2.0.0"}
        assert _version_in_cpe_range("1.5.0", cpe_match) is True

    def test_at_exclusive_end_boundary(self):
        cpe_match = {"versionStartIncluding": "1.0.0", "versionEndExcluding": "2.0.0"}
        assert _version_in_cpe_range("2.0.0", cpe_match) is False

    def test_before_start(self):
        cpe_match = {"versionStartIncluding": "1.0.0", "versionEndExcluding": "2.0.0"}
        assert _version_in_cpe_range("0.9.0", cpe_match) is False

    def test_inclusive_end(self):
        cpe_match = {"versionStartIncluding": "1.0.0", "versionEndIncluding": "2.0.0"}
        assert _version_in_cpe_range("2.0.0", cpe_match) is True

    def test_no_upper_bound_returns_false(self):
        cpe_match = {"versionStartIncluding": "1.0.0"}
        assert _version_in_cpe_range("5.0.0", cpe_match) is False

    def test_exclusive_start(self):
        cpe_match = {"versionStartExcluding": "1.0.0", "versionEndExcluding": "2.0.0"}
        assert _version_in_cpe_range("1.0.0", cpe_match) is False
        assert _version_in_cpe_range("1.0.1", cpe_match) is True


class TestNvdItemAffectsVersion:
    def _make_nvd_item(self, vendor, product, start_incl=None, end_excl=None, end_incl=None):
        cpe_match = {
            "vulnerable": True,
            "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
        }
        if start_incl:
            cpe_match["versionStartIncluding"] = start_incl
        if end_excl:
            cpe_match["versionEndExcluding"] = end_excl
        if end_incl:
            cpe_match["versionEndIncluding"] = end_incl
        return {
            "cve": {
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [cpe_match]
                    }]
                }]
            }
        }

    def test_affected_version(self):
        item = self._make_nvd_item("google", "chrome", start_incl="120.0", end_excl="121.0")
        affected, fixed = _nvd_item_affects_version(item, "120.5", "google", "chrome")
        assert affected is True
        assert fixed == "121.0"

    def test_not_affected_after_fix(self):
        item = self._make_nvd_item("google", "chrome", start_incl="120.0", end_excl="121.0")
        affected, fixed = _nvd_item_affects_version(item, "121.0", "google", "chrome")
        assert affected is False

    def test_wrong_vendor_not_matched(self):
        item = self._make_nvd_item("google", "chrome", start_incl="120.0", end_excl="121.0")
        affected, _ = _nvd_item_affects_version(item, "120.5", "mozilla", "firefox")
        assert affected is False


class TestNvdQueryAppCves:
    def _make_nvd_response(self, cve_id, vendor, product, start_incl, end_excl):
        return {
            "vulnerabilities": [{
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                            }
                        }]
                    },
                    "weaknesses": [],
                    "references": [],
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [{
                                "vulnerable": True,
                                "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": start_incl,
                                "versionEndExcluding": end_excl,
                            }]
                        }]
                    }],
                }
            }]
        }

    @pytest.mark.asyncio
    async def test_query_app_cves_finds_vulnerable_package(self):
        pkg = InstalledPackage(
            name="google-chrome-stable", version="120.0.6099.109-1",
            ecosystem="deb", source="dpkg", arch="amd64",
            purl="pkg:deb/google-chrome-stable@120.0.6099.109-1",
        )
        nvd_response = self._make_nvd_response(
            "CVE-2024-0001", "google", "chrome", "120.0", "121.0"
        )

        client = NvdClient()
        with respx.mock:
            respx.get(NVD_BASE_URL).mock(
                return_value=httpx.Response(200, json=nvd_response)
            )
            result = await client.query_app_cves([pkg], no_cache=True)

        assert len(result) == 1
        assert result[0].cve_id == "CVE-2024-0001"
        assert result[0].fixed_version == "121.0"

    @pytest.mark.asyncio
    async def test_query_app_cves_skips_unmapped_packages(self):
        pkg = InstalledPackage(
            name="some-random-app", version="1.0",
            ecosystem="deb", source="dpkg", arch=None,
            purl="pkg:deb/some-random-app@1.0",
        )
        client = NvdClient()
        result = await client.query_app_cves([pkg], no_cache=True)
        assert result == []

    @pytest.mark.asyncio
    async def test_query_app_cves_skips_unaffected_version(self):
        pkg = InstalledPackage(
            name="firefox", version="130.0",
            ecosystem="snap", source="snap", arch=None,
            purl="pkg:snap/firefox@130.0",
        )
        nvd_response = self._make_nvd_response(
            "CVE-2024-9999", "mozilla", "firefox", "120.0", "125.0"
        )

        client = NvdClient()
        with respx.mock:
            respx.get(NVD_BASE_URL).mock(
                return_value=httpx.Response(200, json=nvd_response)
            )
            result = await client.query_app_cves([pkg], no_cache=True)

        assert result == []

    @pytest.mark.asyncio
    async def test_query_app_cves_handles_network_error(self):
        pkg = InstalledPackage(
            name="google-chrome-stable", version="120.0.6099.109",
            ecosystem="deb", source="dpkg", arch=None,
            purl="pkg:deb/google-chrome-stable@120.0.6099.109",
        )
        client = NvdClient()
        with respx.mock:
            respx.get(NVD_BASE_URL).mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await client.query_app_cves([pkg], no_cache=True)

        assert result == []

    @pytest.mark.asyncio
    async def test_query_app_cves_calls_progress_callback(self):
        pkg = InstalledPackage(
            name="firefox", version="120.0",
            ecosystem="snap", source="snap", arch=None,
            purl="pkg:snap/firefox@120.0",
        )
        nvd_response = self._make_nvd_response(
            "CVE-2024-0002", "mozilla", "firefox", "119.0", "121.0"
        )

        progress_calls = []
        client = NvdClient()
        with respx.mock:
            respx.get(NVD_BASE_URL).mock(
                return_value=httpx.Response(200, json=nvd_response)
            )
            await client.query_app_cves(
                [pkg], no_cache=True,
                progress_cb=lambda cur, total: progress_calls.append((cur, total)),
            )

        assert progress_calls == [(1, 1)]
