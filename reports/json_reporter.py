import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from reports.base_reporter import BaseReporter


class JSONReporter(BaseReporter):

    def _build_report(
        self,
        suspicious_events,
        statistics=None,
        timeline=None,
    ):

        return {

            "generated_at": datetime.now().isoformat(),

            "statistics": (
                asdict(statistics)
                if statistics else None
            ),

            "total_detections": len(suspicious_events),

            "detections": [
                asdict(event)
                for event in suspicious_events
            ],

            "timeline": [
                asdict(entry)
                for entry in timeline
            ] if timeline else []
        }

    def generate(
        self,
        suspicious_events,
        statistics=None,
        timeline=None,
        output_path=None,
    ):

        report = self._build_report(
            suspicious_events,
            statistics,
            timeline,
        )

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with output_path.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
                default=str,
            )