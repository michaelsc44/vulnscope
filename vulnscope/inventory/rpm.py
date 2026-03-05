import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class RpmCollector(BaseCollector):
    def __init__(self, distro_id: str = "linux"):
        self.distro_id = distro_id

    def is_available(self) -> bool:
        return shutil.which("rpm") is not None

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        packages = []
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) != 3:
                continue
            name, version, arch = parts
            if not name or not version:
                continue
            purl = f"pkg:rpm/{self.distro_id}/{name}@{version}?arch={arch}"
            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="rpm",
                    source="rpm",
                    arch=arch,
                    purl=purl,
                )
            )
        return packages
