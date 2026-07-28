from config.constants import LoginStatus, LogSource
from parsers.linux_parser import LinuxParser


def test_failed_login():

    parser = LinuxParser()

    log = (
        "Jul 27 10:15:34 ubuntu sshd[1234]: "
        "Failed password for root from 192.168.1.10 port 44522 ssh2"
    )

    event = parser.parse(log)

    assert event is not None
    assert event.username == "root"
    assert event.source_ip == "192.168.1.10"
    assert event.status == LoginStatus.FAILED
    assert event.log_source == LogSource.LINUX
    assert event.hostname == "ubuntu"
    assert event.service == "sshd"


def test_success_login():

    parser = LinuxParser()

    log = (
        "Jul 27 10:15:34 ubuntu sshd[1234]: "
        "Accepted password for admin from 10.10.10.5 port 5566 ssh2"
    )

    event = parser.parse(log)

    assert event is not None
    assert event.username == "admin"
    assert event.source_ip == "10.10.10.5"
    assert event.status == LoginStatus.SUCCESS


def test_invalid_log():

    parser = LinuxParser()

    log = "This is not a Linux authentication log"

    event = parser.parse(log)

    assert event is None

def test_invalid_user_login():

    parser = LinuxParser()

    log = (
        "Jul 27 10:15:34 ubuntu sshd[1234]: "
        "Failed password for invalid user admin "
        "from 192.168.1.100 port 34567 ssh2"
    )

    event = parser.parse(log)

    assert event is not None
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.100"
    assert event.status == LoginStatus.FAILED