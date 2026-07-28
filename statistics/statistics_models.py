from dataclasses import dataclass, field


@dataclass(frozen=True)
class Statistics:

    total_events: int

    total_detections: int

    detections_by_severity: dict = field(default_factory=dict)

    detections_by_type: dict = field(default_factory=dict)

    top_source_ips: dict = field(default_factory=dict)

    top_usernames: dict = field(default_factory=dict)