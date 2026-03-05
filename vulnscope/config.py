import os
import sys
from pathlib import Path

from platformdirs import user_cache_dir, user_config_dir

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from vulnscope.models import ScanConfig

APP_NAME = "vulnscope"
CONFIG_DIR = Path(user_config_dir(APP_NAME))
CACHE_DIR = Path(user_cache_dir(APP_NAME))
CONFIG_FILE = CONFIG_DIR / "config.toml"
CACHE_DB = CACHE_DIR / "vulndb.sqlite"


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "rb") as f:
            return tomllib.load(f)
    return {}


def get_nvd_api_key(config: dict | None = None) -> str | None:
    key = os.environ.get("NVD_API_KEY")
    if key:
        return key
    if config:
        return config.get("nvd", {}).get("api_key") or None
    return None


def build_scan_config(
    raw: dict,
    no_cache: bool = False,
    scan_docker_contents: bool = False,
    severity_filter: str | None = None,
    ecosystems: list[str] | None = None,
    skip: list[str] | None = None,
) -> ScanConfig:
    scan_section = raw.get("scan", {})
    cache_section = raw.get("cache", {})

    return ScanConfig(
        ecosystems=ecosystems or scan_section.get("ecosystems", ["os", "deb", "rpm", "pypi", "npm", "cargo", "apk"]),
        skip=skip or scan_section.get("skip", []),
        no_cache=no_cache,
        scan_docker_contents=scan_docker_contents or scan_section.get("docker_contents", False),
        severity_filter=severity_filter,
        nvd_api_key=get_nvd_api_key(raw),
        cache_ttl_hours=cache_section.get("ttl_hours", 24),
    )
