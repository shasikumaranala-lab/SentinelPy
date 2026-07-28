from enum import Enum


class LogSource(Enum):
    LINUX = "Linux Authentication"
    APACHE = "Apache Access"
    WINDOWS = "Windows Security"
    AWS = "AWS CloudTrail"


class LoginStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class Severity(Enum):
    LOW = "LOW"

    MEDIUM = "MEDIUM"

    HIGH = "HIGH"

    CRITICAL = "CRITICAL"


class ReportFormat(Enum):
    CSV = "csv"

    JSON = "json"

    CONSOLE = "console"

    HTML = "html"