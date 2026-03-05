import json
import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class PipCollector(BaseCollector):
    def is_available(self) -> bool:
        return shutil.which("python3") is not None or shutil.which("python") is not None

    def _get_interpreters(self) -> list[str]:
        candidates = ["python3", "python"]
        found = []
        seen_paths: set[str] = set()
        for candidate in candidates:
            path = shutil.which(candidate)
            if path and path not in seen_paths:
                seen_paths.add(path)
                found.append(candidate)
        return found

    def _collect_from_interpreter(self, interpreter: str) -> list[InstalledPackage]:
        try:
            result = subprocess.run(
                [interpreter, "-m", "pip", "list", "--format=json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        if result.returncode != 0:
            return []

        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        packages = []
        for pkg in raw:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if not name or not version:
                continue
            purl = f"pkg:pypi/{name.lower()}@{version}"
            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    source=interpreter,
                    arch=None,
                    purl=purl,
                )
            )
        return packages

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []

        all_packages: dict[str, InstalledPackage] = {}
        for interpreter in self._get_interpreters():
            for pkg in self._collect_from_interpreter(interpreter):
                key = f"{pkg.name.lower()}@{pkg.version}"
                if key not in all_packages:
                    all_packages[key] = pkg
        return list(all_packages.values())
