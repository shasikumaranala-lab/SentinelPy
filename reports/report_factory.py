from config.constants import ReportFormat

from reports.json_reporter import JSONReporter
from reports.csv_reporter import CSVReporter
from reports.html_reporter import HTMLReport


class ReportFactory:

    _REPORTERS = {
        ReportFormat.JSON: JSONReporter,
        ReportFormat.CSV: CSVReporter,
        ReportFormat.HTML: HTMLReport,
    }

    @staticmethod
    def get_reporter(report_format: ReportFormat):

        try:
            return ReportFactory._REPORTERS[report_format]()
        except KeyError:
            raise ValueError(
                f"Unsupported report format: {report_format}"
            )