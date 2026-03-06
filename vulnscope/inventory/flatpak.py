import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class FlatpakCollector(BaseCollector):
    def is_available(self) -> bool:
        return shutil.which("flatpak") is not None

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []
        try:
            result = subprocess.run(
                ["flatpak", "list", "--columns=name,application,version,branch"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        packages = []
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) < 4:
                continue
            name, app_id, version, _ = parts[0], parts[1], parts[2], parts[3]
            if not app_id or not version:
                continue
            purl = f"pkg:flatpak/{app_id}@{version}"
            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="flatpak",
                    source="flatpak",
                    arch=None,
                    purl=purl,
                )
            )
        return packages
