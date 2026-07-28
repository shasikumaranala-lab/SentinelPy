from dataclasses import dataclass
from typing import Optional

from models.base_event import BaseEvent


@dataclass(frozen=True)
class CloudEvent(BaseEvent):
    event_name: str
    username: str
    source_ip: str
    aws_region: str
    aws_service: str
    event_source: str

    event_id: Optional[str] = None
    user_agent: Optional[str] = None