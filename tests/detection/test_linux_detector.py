from datetime import datetime, timedelta

from config.constants import LoginStatus, Severity
from detection.linux_detector import LinuxDetector
from models.login_event import LoginEvent


def test_bruteforce_detection():

    detector = LinuxDetector()

    start = datetime.now()

    events = []

    for _ in range(5):

        events.append(
            LoginEvent(
                timestamp=start,
                log_source="LINUX",
                raw_log="failed",
                username="root",
                source_ip="192.168.1.10",
                status=LoginStatus.FAILED,
                service="ssh",
                hostname="ubuntu",
                authentication_method="password",
            )
        )

        start += timedelta(seconds=20)

    detections = detector.analyze(events)

    assert detections[0].severity == Severity.HIGH

    assert detections[0].source_ip == "192.168.1.10"

    assert detections[0].affected_service == "SSH"

    assert detections[0].recommendation is not None
    assert detections[0].detection_name == "SSH Brute Force"