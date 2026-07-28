from timeline.timeline_models import TimelineEntry


class TimelineGenerator:

    def _build_entry(
        self,
        event
    ) -> TimelineEntry:

        return TimelineEntry(

            timestamp=event.timestamp,

            detection_name=event.detection_name,

            severity=event.severity,

            source_ip=event.source_ip,

            username=event.username,

            description=event.description
        )

    def generate(
        self,
        suspicious_events: list
    ) -> list[TimelineEntry]:

        timeline = [

            self._build_entry(event)

            for event in suspicious_events
        ]

        timeline.sort(
            key=lambda entry: entry.timestamp
        )

        return timeline