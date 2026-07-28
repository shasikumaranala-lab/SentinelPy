import json

from config.constants import LoginStatus, LogSource
from parsers.windows_parser import WindowsParser


def test_failed_login():

    parser = WindowsParser()

    log = json.dumps({
        "EventID": 4625,
        "TimeCreated": "2026-07-27T10:15:34",
        "Computer": "WIN-DC01",
        "TargetUserName": "Administrator",
        "IpAddress": "192.168.1.100",
        "LogonType": 3
    })

    event = parser.parse(log)

    assert event is not None
    assert event.username == "Administrator"
    assert event.status == LoginStatus.FAILED
    assert event.log_source == LogSource.WINDOWS


def test_success_login():

    parser = WindowsParser()

    log = json.dumps({
        "EventID": 4624,
        "TimeCreated": "2026-07-27T10:20:15",
        "Computer": "WIN-DC01",
        "TargetUserName": "john",
        "IpAddress": "10.10.10.20",
        "LogonType": 2
    })

    event = parser.parse(log)

    assert event is not None
    assert event.username == "john"
    assert event.status == LoginStatus.SUCCESS


def test_unknown_event():

    parser = WindowsParser()

    log = json.dumps({
        "EventID": 9999
    })

    event = parser.parse(log)

    assert event is None


def test_invalid_json():

    parser = WindowsParser()

    event = parser.parse("Not JSON")

    assert event is None

def test_parse_new_user_creation():
    parser = WindowsParser()

    raw_log = json.dumps({
        "EventID": 4720,
        "TimeCreated": "2025-01-10T10:00:00",
        "TargetUserName": "john",
        "IpAddress": "10.0.0.5",
        "Computer": "DC01"
    })

    event = parser.parse(raw_log)

    assert event is not None
    assert event.event_id == 4720
    assert event.username == "john"

def test_parse_group_change():

    parser = WindowsParser()
    raw_log = json.dumps({

        "EventID": 4728,
        "TimeCreated": "2025-01-10T11:00:00",
        "TargetUserName": "administrator",
        "IpAddress": "192.168.1.20",
        "Computer": "DC01"

    })

    event = parser.parse(raw_log)

    assert event is not None
    assert event.event_id == 4728
    assert event.username == "administrator"
    assert event.source_ip == "192.168.1.20"
    assert event.hostname == "DC01"
    assert event.status is None

def test_parse_account_lockout():

    parser = WindowsParser()
    raw_log = json.dumps({

        "EventID": 4740,
        "TimeCreated": "2025-01-10T12:00:00",
        "TargetUserName": "john",
        "IpAddress": "192.168.1.25",
        "Computer": "DC01"

    })

    event = parser.parse(raw_log)

    assert event is not None
    assert event.event_id == 4740
    assert event.username == "john"
    assert event.source_ip == "192.168.1.25"
    assert event.hostname == "DC01"
    assert event.status is None

def test_parse_special_privileges():

    parser = WindowsParser()

    raw_log = json.dumps({

        "EventID": 4672,
        "TimeCreated": "2025-01-10T13:00:00",
        "TargetUserName": "SYSTEM",
        "IpAddress": "127.0.0.1",
        "Computer": "SERVER01"

    })

    event = parser.parse(raw_log)

    assert event is not None
    assert event.event_id == 4672
    assert event.username == "SYSTEM"
    assert event.source_ip == "127.0.0.1"
    assert event.hostname == "SERVER01"
    assert event.status is None