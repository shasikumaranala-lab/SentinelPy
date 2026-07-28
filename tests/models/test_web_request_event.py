from datetime import datetime

from models.web_request_event import WebRequestEvent


event = WebRequestEvent(
    timestamp=datetime.now(),
    log_source="Apache",
    raw_log='192.168.1.100 - - "GET /index.php HTTP/1.1"',
    client_ip="192.168.1.100",
    http_method="GET",
    url="/index.php",
    status_code=200,
    user_agent="Mozilla/5.0",
    response_size=5234,
    referer="-"
)

print(event)