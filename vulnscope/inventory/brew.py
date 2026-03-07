import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class BrewCollector(BaseCollector):
    def is_available(self) -> bool:
        return shutil.which("brew") is not None

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []

        packages = []
        packages.extend(self._collect_formulae())
        packages.extend(self._collect_casks())
        return packages

    def _collect_formulae(self) -> list[InstalledPackage]:
        return self._run_and_parse(["brew", "list", "--versions"])

    def _collect_casks(self) -> list[InstalledPackage]:
        return self._run_and_parse(["brew", "list", "--cask", "--versions"])

    def _run_and_parse(self, cmd: list[str]) -> list[InstalledPackage]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        packages = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            name = parts[0]
            version = parts[-1]
            purl = f"pkg:brew/{name}@{version}"
            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="brew",
                    source="brew",
                    arch=None,
                    purl=purl,
                )
            )
        return packages
