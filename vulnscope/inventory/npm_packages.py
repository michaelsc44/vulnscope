import json
import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class NpmCollector(BaseCollector):
    def is_available(self) -> bool:
        return shutil.which("npm") is not None

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []
        try:
            result = subprocess.run(
                ["npm", "list", "-g", "--json", "--depth=0"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        packages = []
        for name, info in data.get("dependencies", {}).items():
            version = info.get("version", "")
            if not version:
                continue
            purl = f"pkg:npm/{name}@{version}"
            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    source="npm-global",
                    arch=None,
                    purl=purl,
                )
            )
        return packages
