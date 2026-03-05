import re
import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class CargoCollector(BaseCollector):
    def is_available(self) -> bool:
        return shutil.which("cargo") is not None

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []
        try:
            result = subprocess.run(
                ["cargo", "install", "--list"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        packages = []
        # Format: name v1.2.3:
        #         binary-name
        pattern = re.compile(r"^(\S+)\s+v([\d][^\s:]+):")
        for line in result.stdout.splitlines():
            m = pattern.match(line)
            if not m:
                continue
            name, version = m.group(1), m.group(2)
            purl = f"pkg:cargo/{name}@{version}"
            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="cargo",
                    source="cargo-install",
                    arch=None,
                    purl=purl,
                )
            )
        return packages
