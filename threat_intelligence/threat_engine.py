from config.settings import ENABLE_THREAT_INTELLIGENCE

from threat_intelligence.cache import ThreatCache
from threat_intelligence.abuseipdb_provider import AbuseIPDBProvider


class ThreatEngine:

    def __init__(self):

        self.enabled = ENABLE_THREAT_INTELLIGENCE

        self.cache = ThreatCache()

        self.provider = AbuseIPDBProvider()

    def enrich(self, suspicious_events):

        if not self.enabled:
            return suspicious_events

        for event in suspicious_events:

            ip_address = event.source_ip

            if not ip_address:
                continue

            if self.cache.contains(ip_address):

                event.threat_intel = self.cache.get(ip_address)

                continue

            threat = self.provider.lookup(ip_address)

            if threat is not None:

                self.cache.put(ip_address, threat)

                event.threat_intel = threat

        return suspicious_events