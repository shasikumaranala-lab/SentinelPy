import json
from datetime import datetime

from config.constants import Severity
from models.suspicious_event import SuspiciousEvent
from reports.json_reporter import JSONReporter


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


def test_generate_json_report(tmp_path):

    reporter = JSONReporter()

    output_file = tmp_path / "report.json"

    reporter.generate(
        [create_event()],
        output_file
    )

    assert output_file.exists()

    with output_file.open(
        "r",
        encoding="utf-8"
    ) as file:

        report = json.load(file)

    assert report["total_detections"] == 1
    assert len(report["detections"]) == 1
    assert report["detections"][0]["detection_name"] == "SSH Brute Force"