from datetime import datetime

from config.constants import Severity
from models.suspicious_event import SuspiciousEvent

from reports.html_reporter import HTMLReporter

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

    reporter = HTMLReporter()

    output = tmp_path / "report.html"

    reporter.generate(
        [create_event()],
        output
    )

    assert output.exists()

    html = output.read_text(
        encoding="utf-8"
    )

    assert "SentinelPy Security Report" in html

    assert "SSH Brute Force" in html

    assert "HIGH" in html