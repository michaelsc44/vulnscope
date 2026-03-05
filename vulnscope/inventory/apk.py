import re
import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class ApkCollector(BaseCollector):
    def is_available(self) -> bool:
        return shutil.which("apk") is not None

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []
        try:
            result = subprocess.run(
                ["apk", "list", "--installed"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        packages = []
        # Format: name-version arch {origin} [status]
        # e.g.: musl-1.2.4-r2 x86_64 {musl} [installed]
        pattern = re.compile(r"^(.+?)-(\d[^\s]*)\s+(\S+)")
        for line in result.stdout.splitlines():
            m = pattern.match(line.strip())
            if not m:
                continue
            name, version, arch = m.group(1), m.group(2), m.group(3)
            purl = f"pkg:apk/alpine/{name}@{version}"
            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="apk",
                    source="apk",
                    arch=arch,
                    purl=purl,
                )
            )
        return packages
