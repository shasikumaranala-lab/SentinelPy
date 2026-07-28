from collections import Counter

from statistics.statistics_models import Statistics


class StatisticsGenerator:

    def generate(
        self,
        total_events: int,
        suspicious_events: list
    ) -> Statistics:

        severity_counter = Counter()

        detection_counter = Counter()

        ip_counter = Counter()

        username_counter = Counter()

        for event in suspicious_events:

            severity_counter[event.severity.value] += 1

            detection_counter[event.detection_name] += 1

            if event.source_ip:

                ip_counter[event.source_ip] += 1

            if event.username:

                username_counter[event.username] += 1

        return Statistics(

            total_events=total_events,

            total_detections=len(suspicious_events),

            detections_by_severity=dict(severity_counter),

            detections_by_type=dict(detection_counter),

            top_source_ips=dict(ip_counter.most_common(10)),

            top_usernames=dict(username_counter.most_common(10))
        )