from models.threat_intel import ThreatIntel
from threat_intelligence.cache import ThreatCache

def create_threat():

    return ThreatIntel(

        ip_address="1.1.1.1",

        abuse_confidence_score=95,

        country="Australia",

        isp="Cloudflare",

        domain="cloudflare.com",

        usage_type="CDN",

        total_reports=120,

        provider="AbuseIPDB"
    )

def test_put_and_get():

    cache = ThreatCache()

    threat = create_threat()

    cache.put(
        threat.ip_address,
        threat
    )

    result = cache.get(
        threat.ip_address
    )

    assert result == threat

def test_contains():

    cache = ThreatCache()

    threat = create_threat()

    cache.put(
        threat.ip_address,
        threat
    )

    assert cache.contains(
        threat.ip_address
    )

def test_missing_ip():

    cache = ThreatCache()

    assert cache.get("8.8.8.8") is None

def test_size():

    cache = ThreatCache()

    cache.put(
        "1.1.1.1",
        create_threat()
    )

    assert cache.size() == 1

def test_clear():

    cache = ThreatCache()

    cache.put(
        "1.1.1.1",
        create_threat()
    )

    cache.clear()

    assert cache.size() == 0