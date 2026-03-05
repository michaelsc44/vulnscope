import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class DpkgCollector(BaseCollector):
    def __init__(self, distro_id: str = "linux"):
        self.distro_id = distro_id

    def is_available(self) -> bool:
        return shutil.which("dpkg-query") is not None

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${Status}\n"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        packages = []
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) != 4:
                continue
            name, version, arch, status = parts
            if "install ok installed" not in status:
                continue
            purl = f"pkg:deb/{self.distro_id}/{name}@{version}?arch={arch}"
            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="deb",
                    source="dpkg",
                    arch=arch,
                    purl=purl,
                )
            )
        return packages
