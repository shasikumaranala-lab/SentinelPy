import re
from pathlib import Path
from datetime import datetime

from config.constants import LogSource
from models.web_request_event import WebRequestEvent
from parsers.base_parser import BaseParser


class ApacheParser(BaseParser):

    LOG_PATTERN = re.compile(
        r'(?P<ip>\S+)\s+'
        r'\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+'
        r'(?P<url>\S+)\s+'
        r'(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
    )

    def parse(self, log_file: Path) -> list[WebRequestEvent]:

        events = []

        with log_file.open("r", encoding="utf-8") as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                event = self._parse_line(line)

                if event:
                    events.append(event)

        return events

    def _parse_line(self, raw_log: str) -> WebRequestEvent | None:

        match = self.LOG_PATTERN.match(raw_log)

        if not match:
            return None

        data = match.groupdict()

        timestamp = datetime.strptime(
            data["timestamp"],
            "%d/%b/%Y:%H:%M:%S %z"
        )

        response_size = (
            None if data["size"] == "-"
            else int(data["size"])
        )

        referer = data.get("referer")

        if referer in (None, "-"):
            referer = None

        user_agent = data.get("agent")

        return WebRequestEvent(
            timestamp=timestamp,
            log_source=LogSource.APACHE,
            raw_log=raw_log,
            client_ip=data["ip"],
            http_method=data["method"],
            url=data["url"],
            status_code=int(data["status"]),
            user_agent=user_agent,
            response_size=response_size,
            referer=referer,
        )