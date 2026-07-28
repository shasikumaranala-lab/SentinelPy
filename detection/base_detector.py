from abc import ABC, abstractmethod
from typing import List

from models.suspicious_event import SuspiciousEvent


class BaseDetector(ABC):

    @abstractmethod
    def analyze(self, events) -> List[SuspiciousEvent]:
        pass