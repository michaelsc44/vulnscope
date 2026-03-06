import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx

from vulnscope.databases.cache import CacheDB
from vulnscope.databases.kev import _index_catalog, load_kev_catalog
from vulnscope.databases.nvd import NvdClient
from vulnscope.databases.osv import query_osv_batch
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
