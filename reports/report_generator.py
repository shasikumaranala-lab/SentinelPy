from __future__ import annotations

from pathlib import Path

from config.constants import ReportFormat
from reports.report_factory import ReportFactory
from statistics.statistics_models import Statistics


class ReportGenerator:

    def generate(
        self,
        suspicious_events: list,
        report_format: ReportFormat,
        output_path: Path,
        statistics: Statistics | None = None,
        timeline: list | None = None,
    ) -> None:

        reporter = ReportFactory.get_reporter(report_format)

        reporter.generate(
            suspicious_events=suspicious_events,
            statistics=statistics,
            timeline=timeline,
            output_path=output_path,
        )