from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzer import Analyzer
from config.constants import LogSource, ReportFormat


def test_analyzer_creation():

    analyzer = Analyzer()

    assert analyzer.parser_factory is not None

    assert analyzer.detection_engine is not None

    assert analyzer.threat_engine is not None

    assert analyzer.statistics_generator is not None

    assert analyzer.timeline_generator is not None

    assert analyzer.report_generator is not None

def test_parse_logs():

    analyzer = Analyzer()

    parser = MagicMock()

    parser.parse.return_value = ["event1", "event2"]

    with patch.object(
        analyzer.parser_factory,
        "get_parser",
        return_value=parser
    ):

        events = analyzer.parse_logs(

            LogSource.LINUX,

            Path("auth.log")
        )

    assert events == ["event1", "event2"]

    parser.parse.assert_called_once_with(
        Path("auth.log")
    )

def test_detect_threats():

    analyzer = Analyzer()

    suspicious_events = [
        MagicMock(),
        MagicMock()
    ]

    with patch.object(

        analyzer.detection_engine,

        "analyze",

        return_value=suspicious_events

    ) as mock_analyze:

        result = analyzer.detect_threats(
            LogSource.LINUX,
            ["event1", "event2"]
        )

    assert result == suspicious_events

    mock_analyze.assert_called_once_with(
        LogSource.LINUX,
        ["event1", "event2"]
    )

def test_enrich_threats():

    analyzer = Analyzer()

    enriched_events = [
        MagicMock(),
        MagicMock()
    ]

    with patch.object(

        analyzer.threat_engine,

        "enrich",

        return_value=enriched_events

    ) as mock_enrich:

        result = analyzer.enrich_threats(
            ["event1", "event2"]
        )

    assert result == enriched_events

    mock_enrich.assert_called_once_with(
        ["event1", "event2"]
    )

def test_generate_statistics():

    analyzer = Analyzer()

    statistics = MagicMock()

    with patch.object(

        analyzer.statistics_generator,

        "generate",

        return_value=statistics

    ) as mock_generate:

        result = analyzer.generate_statistics(

            100,

            ["event1", "event2"]
        )

    assert result == statistics

    mock_generate.assert_called_once_with(

        100,

        ["event1", "event2"]
    )

def test_generate_timeline():

    analyzer = Analyzer()

    timeline = [

        MagicMock(),

        MagicMock()
    ]

    with patch.object(

        analyzer.timeline_generator,

        "generate",

        return_value=timeline

    ) as mock_generate:

        result = analyzer.generate_timeline(

            ["event1", "event2"]
        )

    assert result == timeline

    mock_generate.assert_called_once_with(

        ["event1", "event2"]
    )

def test_generate_report():

    analyzer = Analyzer()

    with patch.object(
        analyzer.report_generator,
        "generate"
    ) as mock_generate:

        analyzer.generate_report(
            suspicious_events=[],
            report_format=ReportFormat.JSON,
            output_path=Path("report.json"),
            statistics=None,
            timeline=None
        )

    mock_generate.assert_called_once_with(
        suspicious_events=[],
        report_format=ReportFormat.JSON,
        output_path=Path("report.json"),
        statistics=None,
        timeline=None
    )

def test_analyze():

    analyzer = Analyzer()

    events = ["event1", "event2"]

    suspicious = ["suspicious1"]

    statistics = MagicMock()

    timeline = ["timeline"]

    with (
        patch.object(
            analyzer,
            "parse_logs",
            return_value=events,
        ) as mock_parse,

        patch.object(
            analyzer,
            "detect_threats",
            return_value=suspicious,
        ) as mock_detect,

        patch.object(
            analyzer,
            "enrich_threats",
            return_value=suspicious,
        ) as mock_enrich,

        patch.object(
            analyzer,
            "generate_statistics",
            return_value=statistics,
        ) as mock_statistics,

        patch.object(
            analyzer,
            "generate_timeline",
            return_value=timeline,
        ) as mock_timeline,

        patch.object(
            analyzer,
            "generate_report",
        ) as mock_report,
    ):

        result = analyzer.analyze(

            log_source=LogSource.LINUX,

            log_file=Path("auth.log"),

            report_format=ReportFormat.JSON,

            output_path=Path("report.json"),
        )

    mock_parse.assert_called_once()

    mock_detect.assert_called_once_with(
        LogSource.LINUX,
        events
    )

    mock_enrich.assert_called_once_with(suspicious)

    mock_statistics.assert_called_once_with(

        total_events=2,

        suspicious_events=suspicious,
    )

    mock_timeline.assert_called_once_with(
        suspicious
    )

    mock_report.assert_called_once()

    assert result["events"] == events

    assert result["suspicious_events"] == suspicious

    assert result["statistics"] == statistics

    assert result["timeline"] == timeline