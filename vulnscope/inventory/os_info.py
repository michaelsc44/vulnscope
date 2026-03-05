import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class OSInfo:
    id: str  # "ubuntu", "debian", "fedora", "alpine"
    name: str  # "Ubuntu"
    version: str  # "22.04"
    version_codename: str  # "jammy"
    pretty_name: str  # "Ubuntu 22.04.4 LTS"
    kernel_version: str  # "6.5.0-44-generic"
    arch: str  # "x86_64"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "version_codename": self.version_codename,
            "pretty_name": self.pretty_name,
            "kernel_version": self.kernel_version,
            "arch": self.arch,
        }


def _parse_os_release(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        result[key] = value
    return result


def get_os_info() -> OSInfo:
    os_release: dict[str, str] = {}

    for path in ["/etc/os-release", "/usr/lib/os-release"]:
        p = Path(path)
        if p.exists():
            os_release = _parse_os_release(p.read_text())
            break

    kernel_version = "unknown"
    try:
        result = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            kernel_version = result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    arch = "unknown"
    try:
        result = subprocess.run(["uname", "-m"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            arch = result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return OSInfo(
        id=os_release.get("ID", "linux"),
        name=os_release.get("NAME", "Linux"),
        version=os_release.get("VERSION_ID", "unknown"),
        version_codename=os_release.get("VERSION_CODENAME", ""),
        pretty_name=os_release.get("PRETTY_NAME", "Linux"),
        kernel_version=kernel_version,
        arch=arch,
    )
