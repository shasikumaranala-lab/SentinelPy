import logging
from pathlib import Path
import argparse
import sys

from analyzer import Analyzer
from config.constants import LogSource, ReportFormat
from utils.logger import configure_logger
from config.config_loader import ConfigLoader
from utils.display import (
    print_banner,
    print_configuration,
    print_success,
)

configure_logger()
logger = logging.getLogger(__name__)

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="SentinelPy",
        description="Analyze security logs and generate reports."
    )

    parser.add_argument(
        "--source",
        required=True,
        choices=["linux", "windows", "apache", "aws"],
        help="Log source."
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Input log file."
    )

    parser.add_argument(
        "--format",
        required=True,
        choices=["json", "csv", "html"],
        help="Report format."
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Output report path."
    )

    return parser

def validate_arguments(args) -> None:

    input_file = Path(args.input)

    if not input_file.exists():
        logger.error(f"Error: Input file does not exist: {input_file}")
        sys.exit(1)

    output_path = Path(args.output)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

def main():

    parser = build_parser()
    
    args = parser.parse_args()

    validate_arguments(args)

    config = ConfigLoader.load(
        Path("config/config.yaml")
    )

    configure_logger(
        config.logging.level
    )

    logger.info(
        "%s v%s",
        config.application.name,
        config.application.version,
    )

    print_banner(
        config.application.name,
        config.application.version,
    )

    print_configuration(
        input_file=args.input,
        source=args.source,
        report_format=args.format,
        output_file=args.output,
    )

    print_success(args.output)

    logger.info("Starting SentinelPy...")

    logger.info("Arguments validated.")

    analyzer = Analyzer()

    logger.info("Analyzer initialized.")

    try:

        logger.info("Running analysis...")

        analyzer.analyze(
            log_source=LogSource[args.source.upper()],
            log_file=Path(args.input),
            report_format=ReportFormat[args.format.upper()],
            output_path=Path(args.output),
        )

    except Exception:

        logger.exception("Analysis failed.")

        sys.exit(1)

    logger.info("Analysis completed successfully.")

    logger.info("Report written to %s", args.output)

if __name__ == "__main__":
    main()