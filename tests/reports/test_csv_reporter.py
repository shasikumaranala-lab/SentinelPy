import csv
from datetime import datetime

from config.constants import Severity
from models.suspicious_event import SuspiciousEvent
from reports.csv_reporter import CSVReporter

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

def test_generate_csv_report(tmp_path):

    reporter = CSVReporter()

    output_file = tmp_path / "report.csv"

    reporter.generate(
        [create_event()],
        output_file
    )

    assert output_file.exists()

    with output_file.open(
        "r",
        encoding="utf-8"
    ) as file:

        rows = list(csv.reader(file))

    assert len(rows) == 2

    assert rows[0][0] == "Detection Name"

    assert rows[1][0] == "SSH Brute Force"

    assert rows[1][1] == "HIGH"