from datetime import datetime

from models.login_event import LoginEvent


event = LoginEvent(
    timestamp=datetime.now(),
    log_source="Linux Authentication",
    raw_log="Jul 22 sshd Failed password for root from 192.168.1.15",
    username="root",
    source_ip="192.168.1.15",
    status="FAILED",
    service="sshd",
    hostname="ubuntu-server",
    authentication_method="password"
)

print(event)