import pytest

from config.constants import ReportFormat

from reports.report_factory import ReportFactory
from reports.json_reporter import JSONReporter
from reports.csv_reporter import CSVReporter
from reports.html_reporter import HTMLReport

def test_json_reporter():

    reporter = ReportFactory.get_reporter(
        ReportFormat.JSON
    )

    assert isinstance(
        reporter,
        JSONReporter
    )

def test_csv_reporter():

    reporter = ReportFactory.get_reporter(
        ReportFormat.CSV
    )

    assert isinstance(
        reporter,
        CSVReporter
    )

def test_html_reporter():

    reporter = ReportFactory.get_reporter(
        ReportFormat.HTML
    )

    assert isinstance(
        reporter,
        HTMLReport
    )

def test_invalid_reporter():

    with pytest.raises(ValueError):

        ReportFactory.get_reporter(
            "XML"
        )