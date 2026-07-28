from abc import ABC, abstractmethod
from pathlib import Path


class BaseReporter(ABC):

    @abstractmethod
    def generate(
        self,
        suspicious_events: list,
        output_path: Path,
        statistics=None
    ) -> None:
        pass