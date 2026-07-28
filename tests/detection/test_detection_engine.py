from datetime import datetime

from detection.detection_engine import DetectionEngine

from config.constants import (
    LogSource,
    LoginStatus,
)

from models.login_event import LoginEvent
from models.web_request_event import WebRequestEvent
from models.cloud_event import CloudEvent

def create_linux_event():

    return LoginEvent(

        timestamp=datetime.now(),

        log_source=LogSource.LINUX,

        raw_log="Failed SSH Login",

        username="root",

        source_ip="192.168.1.100",

        status=LoginStatus.FAILED,

        service="SSH",

        hostname="ubuntu",

        authentication_method="password"
    )

def create_apache_event():

    return WebRequestEvent(

        timestamp=datetime.now(),

        log_source=LogSource.APACHE,

        raw_log="Apache Log",

        client_ip="192.168.1.100",

        http_method="GET",

        url="/search?q=' OR 1=1--",

        status_code=200,

        user_agent="Mozilla",

        response_size=512,

        referer=None
    )

def create_windows_event():

    return LoginEvent(

        timestamp=datetime.now(),

        log_source=LogSource.WINDOWS,

        raw_log="Windows Login",

        username="Administrator",

        source_ip="10.10.10.10",

        status=LoginStatus.FAILED,

        service="Windows",

        hostname="DC01",

        authentication_method="Windows",

        event_id=4625
    )

def create_aws_event():

    return CloudEvent(

        timestamp=datetime.now(),

        log_source=LogSource.AWS,

        raw_log="CloudTrail",

        event_name="ConsoleLogin",

        username="root",

        source_ip="52.10.20.30",

        aws_region="us-east-1",

        aws_service="IAM",

        event_source="signin.amazonaws.com",

        event_id="abc123",

        user_agent="Console"
    )

def test_linux_events():

    engine = DetectionEngine()

    detections = engine.analyze([create_linux_event()])

    assert len(detections) == 0

def test_apache_events():

    engine = DetectionEngine()

    detections = engine.analyze([create_apache_event()])

    assert len(detections) == 1

    assert detections[0].affected_service == "Apache"

def test_windows_events():

    engine = DetectionEngine()

    detections = engine.analyze([create_windows_event()])

    assert len(detections) == 0

def test_aws_events():

    engine = DetectionEngine()

    detections = engine.analyze([create_aws_event()])

    assert len(detections) == 1

    assert detections[0].affected_service == "AWS IAM"

def test_multiple_sources():

    engine = DetectionEngine()

    events = [

        create_apache_event(),

        create_aws_event()

    ]

    detections = engine.analyze(events)

    assert len(detections) == 2

def test_empty_events():

    engine = DetectionEngine()

    detections = engine.analyze([])

    assert detections == []