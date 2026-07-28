from abc import ABC, abstractmethod

from models.threat_intel import ThreatIntel


class BaseProvider(ABC):

    @abstractmethod
    def lookup(self, ip_address: str) -> ThreatIntel | None:
        pass