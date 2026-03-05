import httpx

from vulnscope.databases.cache import CacheDB

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def load_kev_catalog(cache: CacheDB | None = None, no_cache: bool = False) -> dict[str, dict]:
    """Return a dict keyed by CVE ID with KEV entry data."""
    if cache and not no_cache:
        cached = cache.get_kev()
        if cached is not None:
            return _index_catalog(cached)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError:
        return {}

    if cache and not no_cache:
        cache.set_kev(data)

    return _index_catalog(data)


def _index_catalog(data: dict) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for entry in data.get("vulnerabilities", []):
        cve_id = entry.get("cveID", "")
        if cve_id:
            result[cve_id] = entry
    return result
