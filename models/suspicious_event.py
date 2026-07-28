from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from config.constants import Severity
from models.threat_intel import ThreatIntel

@dataclass
class SuspiciousEvent:
    detection_name: str
    severity: Severity
    description: str

    timestamp: datetime

    source_ip: Optional[str] = None
    username: Optional[str] = None

    affected_service: Optional[str] = None

    evidence: Optional[str] = None

    recommendation: Optional[str] = None

    threat_intel: ThreatIntel | None = None