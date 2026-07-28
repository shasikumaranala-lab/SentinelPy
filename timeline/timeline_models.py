from dataclasses import dataclass
from datetime import datetime

from config.constants import Severity


@dataclass(frozen=True)
class TimelineEntry:

    timestamp: datetime

    detection_name: str

    severity: Severity

    source_ip: str | None

    username: str | None

    description: str