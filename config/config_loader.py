from pathlib import Path
import yaml

from config.config_models import (
    ApplicationConfig,
    LoggingConfig,
    ReportConfig,
    ThreatIntelConfig,
    AnalysisConfig,
    Config,
)


class ConfigLoader:

    @staticmethod
    def load(path: Path) -> Config:

        with open(path, "r", encoding="utf-8") as file:

            data = yaml.safe_load(file)

        return Config(

            application=ApplicationConfig(
                **data["application"]
            ),

            logging=LoggingConfig(
                **data["logging"]
            ),

            report=ReportConfig(
                **data["report"]
            ),

            threat_intelligence=ThreatIntelConfig(
                **data["threat_intelligence"]
            ),

            analysis=AnalysisConfig(
                **data["analysis"]
            ),
        )

    @staticmethod
    def load_detection_rules():

        with open(
            Path("config/detection_rules.yaml"),
            "r",
            encoding="utf-8",
        ) as file:

            return yaml.safe_load(file)