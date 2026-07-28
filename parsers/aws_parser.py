from pathlib import Path
import json
from datetime import datetime

from config.constants import LogSource
from models.cloud_event import CloudEvent
from parsers.base_parser import BaseParser


class AWSParser(BaseParser):

    SUPPORTED_EVENTS = {
        "ConsoleLogin",
        "CreateUser",
        "CreateAccessKey",
        "AttachUserPolicy",
        "AuthorizeSecurityGroupIngress",
        "StopLogging",
        "DeleteTrail",
        "ListUsers",
        "ListRoles",
        "ListBuckets",
        "GetBucketPolicy",
        "GetObject",
    }

    def parse(self, log_file: Path):

        with log_file.open("r", encoding="utf-8") as file:
            data = json.load(file)

        events = []

        for record in data.get("Records", []):

            event = self._parse_event(record)

            if event:
                events.append(event)

        return events

    def _parse_event(self, data):

        event_name = data.get("eventName")

        if event_name not in self.SUPPORTED_EVENTS:
            return None

        timestamp = datetime.fromisoformat(
            data["eventTime"].replace("Z", "+00:00")
        )

        user_identity = data.get("userIdentity", {})

        return CloudEvent(
            timestamp=timestamp,
            log_source=LogSource.AWS,
            raw_log=json.dumps(data),
            event_name=event_name,
            username=user_identity.get("userName", "Unknown"),
            source_ip=data.get("sourceIPAddress", "Unknown"),
            aws_region=data.get("awsRegion", "Unknown"),
            aws_service=data.get("eventSource", "Unknown"),
            event_source=data.get("eventSource", "Unknown"),
            event_id=data.get("eventID"),
            user_agent=data.get("userAgent"),
        )