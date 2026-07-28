from abc import ABC, abstractmethod


class BaseParser(ABC):
    @abstractmethod
    def parse(self, raw_log: str):
        pass