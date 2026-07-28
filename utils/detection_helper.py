from models.suspicious_event import SuspiciousEvent


def create_detection(
    *,
    detection_name,
    severity,
    description,
    timestamp,
    source_ip,
    username,
    affected_service,
    evidence,
    recommendation,
):

    return SuspiciousEvent(
        detection_name=detection_name,
        severity=severity,
        description=description,
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        affected_service=affected_service,
        evidence=evidence,
        recommendation=recommendation,
    )