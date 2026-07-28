from config.constants import (
    LogSource,
    LoginStatus,
    Severity,
    ReportFormat
)


def test_log_sources():

    assert LogSource.LINUX.value == "Linux Authentication"

    assert LogSource.AWS.value == "AWS CloudTrail"


def test_login_status():

    assert LoginStatus.SUCCESS.value == "SUCCESS"

    assert LoginStatus.FAILED.value == "FAILED"


def test_severity():

    assert Severity.HIGH.value == "HIGH"

    assert Severity.CRITICAL.value == "CRITICAL"


def test_report_format():

    assert ReportFormat.CSV.value == "csv"

    assert ReportFormat.JSON.value == "json"

    assert ReportFormat.CONSOLE.value == "console"