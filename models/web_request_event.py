from dataclasses import dataclass
from typing import Optional

from models.base_event import BaseEvent


@dataclass(frozen=True)
class WebRequestEvent(BaseEvent):
    client_ip: str
    http_method: str
    url: str
    status_code: int
    user_agent: str

    response_size: Optional[int] = None
    referer: Optional[str] = None