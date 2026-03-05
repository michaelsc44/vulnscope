import json
import shutil
import subprocess

from vulnscope.inventory.base import BaseCollector
from vulnscope.models import InstalledPackage


class DockerCollector(BaseCollector):
    def __init__(self, scan_contents: bool = False):
        self.scan_contents = scan_contents

    def is_available(self) -> bool:
        return shutil.which("docker") is not None

    def collect(self) -> list[InstalledPackage]:
        if not self.is_available():
            return []

        try:
            result = subprocess.run(
                ["docker", "image", "ls", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        packages = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                img = json.loads(line)
            except json.JSONDecodeError:
                continue

            repo = img.get("Repository", "")
            tag = img.get("Tag", "latest")
            if not repo or repo == "<none>":
                continue

            name = f"{repo}:{tag}" if tag != "<none>" else repo
            version = tag if tag != "<none>" else "latest"
            purl = f"pkg:docker/{repo}@{tag}"

            packages.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="docker",
                    source="docker",
                    arch=None,
                    purl=purl,
                )
            )

        return packages
