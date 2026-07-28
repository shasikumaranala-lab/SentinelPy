from datetime import datetime

from detection.apache_detector import ApacheDetector
from models.web_request_event import WebRequestEvent
from config.constants import LogSource

def create_event(
    url="/",
    user_agent="Mozilla/5.0",
    method="GET",
    status=200,
):

    return WebRequestEvent(
        timestamp=datetime.now(),
        log_source=LogSource.APACHE,
        raw_log="Sample Apache Log",
        client_ip="192.168.1.100",
        http_method=method,
        url=url,
        status_code=status,
        user_agent=user_agent,
        response_size=512,
        referer=None,
    )

def test_sql_injection_detection():

    detector = ApacheDetector()

    event = create_event(
        url="/login?id=1 UNION SELECT username,password FROM users"
    )

    detections = detector.analyze([event])

    assert len(detections) == 1
    assert detections[0].detection_name == "SQL Injection Attempt"


def test_xss_detection():

    detector = ApacheDetector()

    event = create_event(
        url="/search?q=<script>alert(1)</script>"
    )

    detections = detector.analyze([event])

    assert len(detections) == 1
    assert detections[0].detection_name == "Cross Site Scripting"


def test_directory_traversal_detection():

    detector = ApacheDetector()

    event = create_event(
        url="/download?file=../../etc/passwd"
    )

    detections = detector.analyze([event])

    assert len(detections) == 1
    assert detections[0].detection_name == "Directory Traversal"


def test_scanner_detection():

    detector = ApacheDetector()

    event = create_event(
        user_agent="sqlmap/1.8"
    )

    detections = detector.analyze([event])

    assert len(detections) == 1
    assert detections[0].detection_name == "Scanner Detected"


def test_normal_request():

    detector = ApacheDetector()

    event = create_event(
        url="/home",
        user_agent="Mozilla/5.0"
    )

    detections = detector.analyze([event])

    assert detections == []