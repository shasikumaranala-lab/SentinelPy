import csv
from pathlib import Path

from reports.base_reporter import BaseReporter


class CSVReporter(BaseReporter):

    HEADERS = [
        "Detection Name",
        "Severity",
        "Timestamp",
        "Source IP",
        "Username",
        "Affected Service",
        "Recommendation"
    ]

    def _build_row(self, event):

        return [
            event.detection_name,
            event.severity.value,
            event.timestamp.isoformat(),
            event.source_ip,
            event.username,
            event.affected_service,
            event.recommendation
        ]

    def generate(
        self,
        suspicious_events,
        statistics=None,
        timeline=None,
        output_path=None,
    ):

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with output_path.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow(self.HEADERS)

            for event in suspicious_events:

                writer.writerow(
                    self._build_row(event)
                )