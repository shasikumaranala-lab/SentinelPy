from datetime import datetime

from config.constants import Severity
from timeline.timeline_models import TimelineEntry


def test_timeline_entry():

    entry = TimelineEntry(

        timestamp=datetime.now(),

        detection_name="SSH Brute Force",

        severity=Severity.HIGH,

        source_ip="1.1.1.1",

        username="root",

        description="Multiple failed SSH logins"
    )

    assert entry.detection_name == "SSH Brute Force"

    assert entry.severity == Severity.HIGH

    assert entry.source_ip == "1.1.1.1"

    assert entry.username == "root"