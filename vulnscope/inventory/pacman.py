import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class PacmanCollector(BaseCollector):
    def is_available(self) -> bool:
        return shutil.which("pacman") is not None

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []
        try:
            result = subprocess.run(
                ["pacman", "-Q"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        packages = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) != 2:
                continue
            name, version = parts
            purl = f"pkg:pacman/arch/{name}@{version}"
            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="pacman",
                    source="pacman",
                    arch=None,
                    purl=purl,
                )
            )
        return packages
