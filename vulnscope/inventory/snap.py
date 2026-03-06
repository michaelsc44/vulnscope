import re
import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class SnapCollector(BaseCollector):
    def is_available(self) -> bool:
        return shutil.which("snap") is not None

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []
        try:
            result = subprocess.run(
                ["snap", "list"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        packages = []
        lines = result.stdout.splitlines()
        # Skip header line
        for line in lines[1:]:
            parts = re.split(r"\s+", line.strip())
            if len(parts) < 3:
                continue
            name, version = parts[0], parts[1]
            if not name or not version:
                continue
            # Skip base snaps that aren't real applications
            if name in ("bare", "core", "core18", "core20", "core22", "core24",
                        "gtk-common-themes", "gnome-3-38-2004", "gnome-42-2204",
                        "gnome-46-2404", "snapd", "snapd-desktop-integration",
                        "firmware-updater", "snap-store"):
                continue
            purl = f"pkg:snap/{name}@{version}"
            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="snap",
                    source="snap",
                    arch=None,
                    purl=purl,
                )
            )
        return packages
