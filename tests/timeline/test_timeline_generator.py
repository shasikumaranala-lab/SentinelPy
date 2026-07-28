from datetime import datetime, timedelta

from config.constants import Severity
from models.suspicious_event import SuspiciousEvent
from timeline.timeline_generator import TimelineGenerator

def create_event(timestamp):

    return SuspiciousEvent(

        detection_name="SSH Brute Force",

        severity=Severity.HIGH,

        description="Multiple failed SSH logins",

        timestamp=timestamp,

        source_ip="1.1.1.1",

        username="root",

        affected_service="SSH",

        evidence=None,

        recommendation="Investigate",

        threat_intel=None
    )

def test_generate_timeline():

    now = datetime.now()

    events = [

        create_event(now + timedelta(minutes=20)),

        create_event(now),

        create_event(now + timedelta(minutes=10))
    ]

    generator = TimelineGenerator()

    timeline = generator.generate(events)

    assert len(timeline) == 3

    assert timeline[0].timestamp == now

    assert timeline[1].timestamp == now + timedelta(minutes=10)

    assert timeline[2].timestamp == now + timedelta(minutes=20)