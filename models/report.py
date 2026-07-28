from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from config.constants import Severity


@dataclass(frozen=True)
class Report:
    timestamp: datetime

    detection_name: str

    severity: Severity

    description: str

    source_ip: Optional[str] = None

    username: Optional[str] = None

    affected_service: Optional[str] = None

    country: Optional[str] = None

    isp: Optional[str] = None

    threat_score: Optional[int] = None

    recommendation: Optional[str] = None