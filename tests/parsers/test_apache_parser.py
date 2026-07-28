from config.constants import LogSource
from parsers.apache_parser import ApacheParser


def test_valid_log(tmp_path):

    parser = ApacheParser()

    log = (
        '192.168.1.100 - - '
        '[27/Jul/2026:10:15:34 +0530] '
        '"GET /login HTTP/1.1" '
        '200 512 '
        '"https://example.com" '
        '"Mozilla/5.0"'
    )

    log_file = tmp_path / "access.log"
    log_file.write_text(log)

    events = parser.parse(log_file)

    assert len(events) == 1

    event = events[0]

    assert event.client_ip == "192.168.1.100"
    assert event.http_method == "GET"
    assert event.url == "/login"
    assert event.status_code == 200
    assert event.response_size == 512
    assert event.log_source == LogSource.APACHE


def test_dash_size(tmp_path):

    parser = ApacheParser()

    log = (
        '192.168.1.100 - - '
        '[27/Jul/2026:10:15:34 +0530] '
        '"GET /favicon.ico HTTP/1.1" '
        '404 - '
        '"-" '
        '"curl/8.0"'
    )

    log_file = tmp_path / "access.log"
    log_file.write_text(log)

    events = parser.parse(log_file)

    assert len(events) == 1

    event = events[0]

    assert event.response_size is None
    assert event.referer is None


def test_invalid_log(tmp_path):

    parser = ApacheParser()

    log_file = tmp_path / "access.log"
    log_file.write_text("Not an apache log")

    events = parser.parse(log_file)

    assert events == []