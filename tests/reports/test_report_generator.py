from pathlib import Path
from unittest.mock import MagicMock, patch

from config.constants import ReportFormat

from reports.report_generator import ReportGenerator

def test_generate_report():

    generator = ReportGenerator()

    reporter = MagicMock()

    with patch(
        "reports.report_generator.ReportFactory.get_reporter",
        return_value=reporter
    ):

        generator.generate(
            suspicious_events=[],
            report_format=ReportFormat.JSON,
            output_path=Path("report.json"),
            statistics=None
        )

        reporter.generate.assert_called_once()