from models.threat_intel import ThreatIntel


intel = ThreatIntel(
    ip_address="8.8.8.8",
    abuse_confidence_score=92,
    country="US",
    isp="Google LLC",
    domain="google.com",
    usage_type="Data Center",
    total_reports=315
)

print(intel)