from abc import ABC, abstractmethod

from vulnscope.models import InstalledPackage, Vulnerability


class BaseDatabase(ABC):
    @abstractmethod
    async def query_packages(self, packages: list[InstalledPackage]) -> list[Vulnerability]:
        """Query this database for vulnerabilities affecting the given packages."""
