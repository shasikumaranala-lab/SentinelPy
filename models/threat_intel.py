from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ThreatIntel:
    ip_address: str

    abuse_confidence_score: int

    country: Optional[str] = None

    isp: Optional[str] = None

    domain: Optional[str] = None

    usage_type: Optional[str] = None

    total_reports: Optional[int] = None

    provider: str = "AbuseIPDB"