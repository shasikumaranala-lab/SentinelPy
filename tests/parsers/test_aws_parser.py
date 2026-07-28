import json

from config.constants import LogSource
from parsers.aws_parser import AWSParser


def test_console_login():

    parser = AWSParser()

    log = json.dumps({
        "eventTime": "2026-07-27T10:15:34Z",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "awsRegion": "ap-south-1",
        "sourceIPAddress": "203.122.10.15",
        "userAgent": "Mozilla/5.0",
        "eventID": "12345678",
        "userIdentity": {
            "userName": "admin"
        }
    })

    event = parser.parse(log)

    assert event is not None
    assert event.event_name == "ConsoleLogin"
    assert event.username == "admin"
    assert event.aws_region == "ap-south-1"
    assert event.log_source == LogSource.AWS


def test_create_user():

    parser = AWSParser()

    log = json.dumps({
        "eventTime": "2026-07-27T10:15:34Z",
        "eventName": "CreateUser",
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "ap-south-1",
        "sourceIPAddress": "10.10.10.10",
        "eventID": "abcd",
        "userIdentity": {
            "userName": "root"
        }
    })

    event = parser.parse(log)

    assert event is not None
    assert event.event_name == "CreateUser"


def test_unknown_event():

    parser = AWSParser()

    log = json.dumps({
        "eventName": "DeleteBucket"
    })

    assert parser.parse(log) is None


def test_invalid_json():

    parser = AWSParser()

    assert parser.parse("Invalid JSON") is None