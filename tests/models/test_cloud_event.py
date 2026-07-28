from datetime import datetime

from models.cloud_event import CloudEvent


event = CloudEvent(
    timestamp=datetime.now(),
    log_source="AWS CloudTrail",
    raw_log='{"eventName":"CreateUser"}',
    event_name="CreateUser",
    username="admin",
    source_ip="192.168.10.25",
    aws_region="ap-south-1",
    aws_service="IAM",
    event_source="iam.amazonaws.com",
    event_id="1234-abcd-5678",
    user_agent="AWS Console"
)

print(event)