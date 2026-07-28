from datetime import datetime

from models.base_event import BaseEvent


event = BaseEvent(
    timestamp=datetime.now(),
    log_source="Linux Authentication",
    raw_log="Jul 22 sshd Failed password..."
)

print(event)