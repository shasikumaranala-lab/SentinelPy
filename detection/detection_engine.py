from collections import defaultdict

from config.constants import LogSource

from detection.linux_detector import LinuxDetector
from detection.apache_detector import ApacheDetector
from detection.windows_detector import WindowsDetector
from detection.aws_detector import AWSDetector
from models.base_event import BaseEvent


class DetectionEngine:

    def analyze(
        self,
        log_source: LogSource,
        events: list[BaseEvent]
    ):

        if log_source == LogSource.LINUX:
            detector = LinuxDetector()

        elif log_source == LogSource.WINDOWS:
            detector = WindowsDetector()

        elif log_source == LogSource.APACHE:
            detector = ApacheDetector()

        elif log_source == LogSource.AWS:
            detector = AWSDetector()

        else:
            raise ValueError(
                f"Unsupported log source: {log_source}"
            )

        return detector.analyze(events)