from dataclasses import dataclass


@dataclass(frozen=True)
class LoggingConfig:
    level: str


@dataclass(frozen=True)
class ReportConfig:
    default_format: str
    output_directory: str


@dataclass(frozen=True)
class ThreatIntelConfig:
    enabled: bool


@dataclass(frozen=True)
class AnalysisConfig:
    save_timeline: bool
    generate_statistics: bool


@dataclass(frozen=True)
class ApplicationConfig:
    name: str
    version: str


@dataclass(frozen=True)
class Config:

    application: ApplicationConfig

    logging: LoggingConfig

    report: ReportConfig

    threat_intelligence: ThreatIntelConfig

    analysis: AnalysisConfig