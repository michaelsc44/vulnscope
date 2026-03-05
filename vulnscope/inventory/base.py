from abc import ABC, abstractmethod

from vulnscope.models import InstalledPackage


class BaseCollector(ABC):
    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this collector can run on the current system."""

    @abstractmethod
    def collect(self) -> list[InstalledPackage]:
        """Collect installed packages. Returns empty list if unavailable or on error."""
