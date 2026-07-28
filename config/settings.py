from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SAMPLE_LOGS_DIR = PROJECT_ROOT / "sample_logs"

OUTPUT_DIR = PROJECT_ROOT / "output"

REPORTS_DIR = OUTPUT_DIR / "reports"

OUTPUT_LOGS_DIR = OUTPUT_DIR / "logs"

MAX_FAILED_LOGINS = 5

BRUTE_FORCE_TIME_WINDOW = 300

ENABLE_THREAT_INTELLIGENCE = True

DEFAULT_REPORT_NAME = "sentinel_report"

DEFAULT_REPORT_ENCODING = "utf-8"

LOG_LEVEL = "INFO"

LOG_FILE_NAME = "sentinel.log"

ABUSE_IPDB_TIMEOUT = 30

PASSWORD_SPRAY_THRESHOLD = 5

# Threat Intelligence

ABUSEIPDB_API_KEY = ""

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

ABUSEIPDB_TIMEOUT = 10

ENABLE_THREAT_INTELLIGENCE = True