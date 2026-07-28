import json
from pathlib import Path
from datetime import datetime

from config.constants import LogSource, LoginStatus
from models.login_event import LoginEvent
from parsers.base_parser import BaseParser

SUPPORTED_EVENTS = {
    4624,
    4625,
    4720,
    4726,
    4728,
    4732,
    4740,
    4672,
}


class WindowsParser(BaseParser):

    def parse(self, log_file: Path) -> list[LoginEvent]:

        events = []

        with log_file.open("r", encoding="utf-8") as file:
            records = json.load(file)

        for record in records:

            event = self._parse_event(record)

            if event:
                events.append(event)

        return events


    def _parse_event(self, data: dict) -> LoginEvent | None:

        event_id = data.get("EventID")

        if event_id not in SUPPORTED_EVENTS:
            return None

        status = None

        if event_id == 4624:
            status = LoginStatus.SUCCESS

        elif event_id == 4625:
            status = LoginStatus.FAILED

        timestamp = datetime.fromisoformat(
            data["timestamp"].replace("Z", "+00:00")
        )

        return LoginEvent(

            timestamp=timestamp,

            log_source=LogSource.WINDOWS,

            raw_log=json.dumps(data),

            username=data.get("TargetUserName"),

            source_ip=data.get("IpAddress"),

            status=status,

            service="Windows",

            hostname=data.get("Computer"),

            authentication_method="Windows",

            event_id=event_id,
        )