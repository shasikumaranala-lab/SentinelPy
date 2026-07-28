from datetime import datetime

from config.constants import Severity
from models.suspicious_event import SuspiciousEvent

from reports.html_reporter import HTMLReport
from statistics.statistics_models import Statistics

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

def test_generate_html_report(tmp_path):

    reporter = HTMLReport()

    output = tmp_path / "report.html"

    statistics = Statistics(
        total_events=1,
        total_detections=1,
        detections_by_severity={
            "HIGH": 1
        },
        detections_by_type={
            "SSH Brute Force": 1
        },
        top_source_ips={
            "1.1.1.1": 1
        },
        top_usernames={
            "root": 1
        }
    )

    reporter.generate(
        suspicious_events=[create_event()],
        statistics=statistics,
        timeline=[],
        output_path=output
    )

    assert output.exists()

    html = output.read_text(
        encoding="utf-8"
    )

    assert "SentinelPy Security Report" in html

    assert "SSH Brute Force" in html

    assert "HIGH" in html