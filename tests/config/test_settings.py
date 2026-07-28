from config.settings import (
    PROJECT_ROOT,
    SAMPLE_LOGS_DIR,
    OUTPUT_DIR,
    REPORTS_DIR,
    OUTPUT_LOGS_DIR,
    MAX_FAILED_LOGINS,
    BRUTE_FORCE_TIME_WINDOW,
    ENABLE_THREAT_INTELLIGENCE,
    DEFAULT_REPORT_NAME,
    DEFAULT_REPORT_ENCODING,
    LOG_LEVEL,
    LOG_FILE_NAME,
    ABUSE_IPDB_TIMEOUT
)


def test_paths():

    assert PROJECT_ROOT.exists()

    assert SAMPLE_LOGS_DIR.name == "sample_logs"

    assert OUTPUT_DIR.name == "output"

    assert REPORTS_DIR.name == "reports"

    assert OUTPUT_LOGS_DIR.name == "logs"


def test_detection_settings():

    assert MAX_FAILED_LOGINS == 5

    assert BRUTE_FORCE_TIME_WINDOW == 300

    assert ENABLE_THREAT_INTELLIGENCE is True


def test_report_settings():

    assert DEFAULT_REPORT_NAME == "sentinel_report"

    assert DEFAULT_REPORT_ENCODING == "utf-8"


def test_logging_settings():

    assert LOG_LEVEL == "INFO"

    assert LOG_FILE_NAME == "sentinel.log"


def test_threat_settings():

    assert ABUSE_IPDB_TIMEOUT == 30