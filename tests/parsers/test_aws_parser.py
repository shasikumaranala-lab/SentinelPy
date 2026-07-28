import json

from config.constants import LogSource
from parsers.aws_parser import AWSParser


def write_log(tmp_path, records):

    log_file = tmp_path / "cloudtrail.json"

    log_file.write_text(json.dumps({"Records": records}))

    return log_file


def test_console_login(tmp_path):

    parser = AWSParser()

    log_file = write_log(tmp_path, [
        {
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
        }
    ])

    events = parser.parse(log_file)

    assert len(events) == 1

    event = events[0]

    assert event.event_name == "ConsoleLogin"
    assert event.username == "admin"
    assert event.aws_region == "ap-south-1"
    assert event.log_source == LogSource.AWS


def test_create_user(tmp_path):

    parser = AWSParser()

    log_file = write_log(tmp_path, [
        {
            "eventTime": "2026-07-27T10:15:34Z",
            "eventName": "CreateUser",
            "eventSource": "iam.amazonaws.com",
            "awsRegion": "ap-south-1",
            "sourceIPAddress": "10.10.10.10",
            "eventID": "abcd",
            "userIdentity": {
                "userName": "root"
            }
        }
    ])

    events = parser.parse(log_file)

    assert len(events) == 1

    event = events[0]

    assert event.event_name == "CreateUser"


def test_unknown_event(tmp_path):

    parser = AWSParser()

    log_file = write_log(tmp_path, [
        {
            "eventName": "DeleteBucket",
            "eventTime": "2026-07-27T10:15:34Z"
        }
    ])

    events = parser.parse(log_file)

    assert events == []


def test_invalid_json(tmp_path):

    parser = AWSParser()

    log_file = tmp_path / "cloudtrail.json"

    log_file.write_text("Invalid JSON")

    try:
        parser.parse(log_file)
        assert False
    except json.JSONDecodeError:
        pass