import logging

from detection.detection_engine import DetectionEngine
from parsers.parser_factory import ParserFactory
from reports.report_generator import ReportGenerator
from statistics.statistics_generator import StatisticsGenerator
from threat_intelligence.threat_engine import ThreatEngine
from timeline.timeline_generator import TimelineGenerator
from pathlib import Path

from config.constants import LogSource
from models.base_event import BaseEvent
from config.constants import ReportFormat
from statistics.statistics_models import Statistics

logger = logging.getLogger(__name__)


class Analyzer:

    def __init__(self):

        self.parser_factory = ParserFactory()

        self.detection_engine = DetectionEngine()

        self.threat_engine = ThreatEngine()

        self.statistics_generator = StatisticsGenerator()

        self.timeline_generator = TimelineGenerator()

        self.report_generator = ReportGenerator()

    def parse_logs(
        self,
        log_source: LogSource,
        log_file: Path
    ) -> list[BaseEvent]:

        logger.info("Parsing logs...")

        parser = self.parser_factory.get_parser(
            log_source
        )

        return parser.parse(log_file)

    def detect_threats(
        self,
        log_source: LogSource,
        events: list[BaseEvent]
    ):

        logger.info("Running detections...")

        return self.detection_engine.analyze(
            log_source,
            events
        )

    def enrich_threats(
        self,
        suspicious_events: list
    ):

        logger.info("Enriching threat intelligence...")

        return self.threat_engine.enrich(
            suspicious_events
        )

    def generate_statistics(
        self,
        total_events: int,
        suspicious_events: list
    ):

        logger.info("Generating statistics...")

        return self.statistics_generator.generate(
            total_events,
            suspicious_events
        )

    def generate_timeline(
        self,
        suspicious_events: list
    ):

        logger.info("Generating timeline...")

        return self.timeline_generator.generate(
            suspicious_events
        )

    def generate_report(
        self,
        suspicious_events,
        report_format,
        output_path,
        statistics=None,
        timeline=None,
    ):

        logger.info("Generating report...")

        self.report_generator.generate(
            suspicious_events=suspicious_events,
            report_format=report_format,
            output_path=output_path,
            statistics=statistics,
            timeline=timeline,
        )

    def analyze(
        self,
        log_source: LogSource,
        log_file: Path,
        report_format: ReportFormat,
        output_path: Path,
    ):

        # Step 1
        events = self.parse_logs(
            log_source,
            log_file,
        )

        # Step 2
        suspicious_events = self.detect_threats(
            log_source,
            events
        )

        # Step 3
        enriched_events = self.enrich_threats(
            suspicious_events
        )

        # Step 4
        statistics = self.generate_statistics(
            total_events=len(events),
            suspicious_events=enriched_events,
        )

        # Step 5
        timeline = self.generate_timeline(
            enriched_events
        )

        # Step 6
        self.generate_report(
            suspicious_events=enriched_events,
            report_format=report_format,
            output_path=output_path,
            statistics=statistics,
            timeline=timeline,
        )

        return {
            "events": events,
            "suspicious_events": enriched_events,
            "statistics": statistics,
            "timeline": timeline,
        }