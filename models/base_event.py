from dataclasses import dataclass
from datetime import datetime
from config.constants import LogSource


@dataclass(frozen=True)
class BaseEvent:

    timestamp: datetime
    log_source: LogSource
    raw_log: str