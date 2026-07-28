from datetime import datetime

from config.constants import Severity

from models.suspicious_event import SuspiciousEvent

from statistics.statistics_generator import StatisticsGenerator

def create_event():

    return SuspiciousEvent(

        detection_name="SSH Brute Force",

        severity=Severity.HIGH,

        description="Multiple failed logins",

        timestamp=datetime.now(),

        source_ip="1.1.1.1",

        username="root",

        affected_service="SSH",

        evidence=None,

        recommendation="Investigate",

        threat_intel=None
    )

def test_generate_statistics():

    generator = StatisticsGenerator()

    events = [
        create_event(),
        create_event(),
        create_event()
    ]

    statistics = generator.generate(

        total_events=100,

        suspicious_events=events
    )

    assert statistics.total_events == 100

    assert statistics.total_detections == 3

    assert statistics.detections_by_severity["HIGH"] == 3

    assert statistics.detections_by_type["SSH Brute Force"] == 3

    assert statistics.top_source_ips["1.1.1.1"] == 3

    assert statistics.top_usernames["root"] == 3