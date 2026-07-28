from datetime import datetime

from config.constants import Severity

from models.suspicious_event import SuspiciousEvent
from models.threat_intel import ThreatIntel

from threat_intelligence.threat_engine import ThreatEngine
from unittest.mock import patch

def create_event():

    return SuspiciousEvent(

        timestamp=datetime.now(),

        severity=Severity.HIGH,

        detection_name="SSH Brute Force",

        description="Multiple failed logins",

        source_ip="1.1.1.1",

        username="root",

        affected_service="SSH",

        recommendation="Investigate"

    )

def create_threat():

    return ThreatIntel(

        ip_address="1.1.1.1",

        abuse_confidence_score=95,

        country="Australia",

        isp="Cloudflare",

        domain="cloudflare.com",

        usage_type="CDN",

        total_reports=100,

        provider="AbuseIPDB"
    )

def test_disabled_engine():

    engine = ThreatEngine()

    engine.enabled = False

    events = [create_event()]

    result = engine.enrich(events)

    assert result == events

def test_cache_hit():

    engine = ThreatEngine()

    threat = create_threat()

    engine.cache.put("1.1.1.1", threat)

    events = [create_event()]

    result = engine.enrich(events)

    assert result[0].threat_intel == threat

def test_provider_lookup():

    engine = ThreatEngine()

    threat = create_threat()

    with patch.object(
        engine.provider,
        "lookup",
        return_value=threat
    ):

        events = [create_event()]

        result = engine.enrich(events)

        assert result[0].threat_intel == threat