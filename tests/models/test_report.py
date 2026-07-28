from datetime import datetime

from models.report import Report


report = Report(
    timestamp=datetime.now(),

    detection_name="SSH Brute Force",

    severity="HIGH",

    description="Multiple failed SSH logins detected.",

    source_ip="192.168.1.15",

    username="root",

    affected_service="sshd",

    country="US",

    isp="Google LLC",

    threat_score=92,

    recommendation="Block IP and investigate."
)

print(report)