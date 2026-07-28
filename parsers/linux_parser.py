import re
from datetime import datetime

from config.constants import LogSource, LoginStatus
from models.login_event import LoginEvent
from parsers.base_parser import BaseParser
from pathlib import Path


class LinuxParser(BaseParser):
    FAILED_LOGIN_PATTERN = re.compile(
        r"^(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>\w+)\[\d+\]:\s+"
        r"Failed password for (?:invalid user\s+)?"
        r"(?P<username>\S+)\s+from\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    SUCCESS_LOGIN_PATTERN = re.compile(
        r"^(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>\w+)\[\d+\]:\s+"
        r"Accepted password for (?P<username>\S+)\s+from\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    def _parse_line(self, raw_log: str) -> LoginEvent | None:

        failed_match = self.FAILED_LOGIN_PATTERN.match(raw_log)

        if failed_match:
            return self._create_event(
                failed_match,
                raw_log,
                LoginStatus.FAILED
            )

        success_match = self.SUCCESS_LOGIN_PATTERN.match(raw_log)

        if success_match:
            return self._create_event(
                success_match,
                raw_log,
                LoginStatus.SUCCESS
            )

        return None

    def _create_event(self, match, raw_log, status):

        data = match.groupdict()

        current_year = datetime.now().year

        timestamp = datetime.strptime(
            f"{current_year} {data['month']} {data['day']} {data['time']}",
            "%Y %b %d %H:%M:%S"
        )

        return LoginEvent(
            timestamp=timestamp,
            log_source=LogSource.LINUX,
            raw_log=raw_log,
            username=data["username"],
            source_ip=data["ip"],
            status=status,
            service=data["service"],
            hostname=data["hostname"],
            authentication_method="password",
        )

    def parse(self, log_file: Path):

        events = []

        with open(
            log_file,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                event = self._parse_line(line)

                if event:
                    events.append(event)

        return events