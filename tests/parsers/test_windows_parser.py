import json

from config.constants import LoginStatus, LogSource
from parsers.windows_parser import WindowsParser


def write_log(tmp_path, records):

    log_file = tmp_path / "security.json"

    log_file.write_text(json.dumps(records))

    return log_file


def test_failed_login(tmp_path):

    parser = WindowsParser()

    log_file = write_log(tmp_path, [
        {
            "EventID": 4625,
            "timestamp": "2026-07-27T10:15:34Z",
            "Computer": "WIN-DC01",
            "TargetUserName": "Administrator",
            "IpAddress": "192.168.1.100"
        }
    ])

    events = parser.parse(log_file)

    assert len(events) == 1

    event = events[0]

    assert event.username == "Administrator"
    assert event.status == LoginStatus.FAILED
    assert event.log_source == LogSource.WINDOWS


def test_success_login(tmp_path):

    parser = WindowsParser()

    log_file = write_log(tmp_path, [
        {
            "EventID": 4624,
            "timestamp": "2026-07-27T10:20:15Z",
            "Computer": "WIN-DC01",
            "TargetUserName": "john",
            "IpAddress": "10.10.10.20"
        }
    ])

    events = parser.parse(log_file)

    assert len(events) == 1

    event = events[0]

    assert event.username == "john"
    assert event.status == LoginStatus.SUCCESS


def test_unknown_event(tmp_path):

    parser = WindowsParser()

    log_file = write_log(tmp_path, [
        {
            "EventID": 9999,
            "timestamp": "2026-07-27T10:20:15Z"
        }
    ])

    events = parser.parse(log_file)

    assert events == []


def test_invalid_json(tmp_path):

    parser = WindowsParser()

    log_file = tmp_path / "security.json"

    log_file.write_text("Not JSON")

    try:
        parser.parse(log_file)
        assert False
    except json.JSONDecodeError:
        pass


def test_parse_new_user_creation(tmp_path):

    parser = WindowsParser()

    log_file = write_log(tmp_path, [
        {
            "EventID": 4720,
            "timestamp": "2025-01-10T10:00:00Z",
            "TargetUserName": "john",
            "IpAddress": "10.0.0.5",
            "Computer": "DC01"
        }
    ])

    events = parser.parse(log_file)

    assert len(events) == 1

    event = events[0]

    assert event.event_id == 4720
    assert event.username == "john"


def test_parse_group_change(tmp_path):

    parser = WindowsParser()

    log_file = write_log(tmp_path, [
        {
            "EventID": 4728,
            "timestamp": "2025-01-10T11:00:00Z",
            "TargetUserName": "administrator",
            "IpAddress": "192.168.1.20",
            "Computer": "DC01"
        }
    ])

    events = parser.parse(log_file)

    assert len(events) == 1

    event = events[0]

    assert event.event_id == 4728
    assert event.username == "administrator"
    assert event.source_ip == "192.168.1.20"
    assert event.hostname == "DC01"
    assert event.status is None


def test_parse_account_lockout(tmp_path):

    parser = WindowsParser()

    log_file = write_log(tmp_path, [
        {
            "EventID": 4740,
            "timestamp": "2025-01-10T12:00:00Z",
            "TargetUserName": "john",
            "IpAddress": "192.168.1.25",
            "Computer": "DC01"
        }
    ])

    events = parser.parse(log_file)

    assert len(events) == 1

    event = events[0]

    assert event.event_id == 4740
    assert event.username == "john"


def test_parse_special_privileges(tmp_path):

    parser = WindowsParser()

    log_file = write_log(tmp_path, [
        {
            "EventID": 4672,
            "timestamp": "2025-01-10T13:00:00Z",
            "TargetUserName": "SYSTEM",
            "IpAddress": "127.0.0.1",
            "Computer": "SERVER01"
        }
    ])

    events = parser.parse(log_file)

    assert len(events) == 1

    event = events[0]

    assert event.event_id == 4672
    assert event.username == "SYSTEM"