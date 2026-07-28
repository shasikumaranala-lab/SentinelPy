from dataclasses import dataclass
from typing import Optional

from models.base_event import BaseEvent
from config.constants import LoginStatus


@dataclass(frozen=True)
class LoginEvent(BaseEvent):

    username: str
    source_ip: str
    status: LoginStatus
    service: str
    hostname: str
    authentication_method: Optional[str] = None
    event_id: int | None = None