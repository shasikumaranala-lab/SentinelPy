from datetime import datetime

from models.suspicious_event import SuspiciousEvent


event = SuspiciousEvent(
    detection_name="SSH Brute Force",

    severity="HIGH",

    description="Multiple failed SSH logins.",

    timestamp=datetime.now(),

    source_ip="192.168.1.15",

    username="root",

    affected_service="sshd",

    evidence="15 failures in 5 minutes",

    recommendation="Block IP immediately."
)

print(event)