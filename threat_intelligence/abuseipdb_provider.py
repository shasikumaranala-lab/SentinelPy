import requests

from config.settings import (
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_TIMEOUT,
    ABUSEIPDB_URL,
)

from models.threat_intel import ThreatIntel

from threat_intelligence.base_provider import BaseProvider


class AbuseIPDBProvider(BaseProvider):

    def __init__(self):

        self.api_key = ABUSEIPDB_API_KEY

        self.url = ABUSEIPDB_URL

        self.timeout = ABUSEIPDB_TIMEOUT

    def lookup(self, ip_address: str) -> ThreatIntel | None:

        if not self.api_key:
            return None

        headers = {

            "Key": self.api_key,

            "Accept": "application/json"

        }

        params = {

            "ipAddress": ip_address,

            "maxAgeInDays": 90

        }

        try:

            response = requests.get(

                self.url,

                headers=headers,

                params=params,

                timeout=self.timeout

            )

            response.raise_for_status()

            data = response.json()["data"]

            return ThreatIntel(

                ip_address=data["ipAddress"],

                abuse_confidence_score=data["abuseConfidenceScore"],

                country=data.get("countryCode"),

                isp=data.get("isp"),

                domain=data.get("domain"),

                usage_type=data.get("usageType"),

                total_reports=data.get("totalReports"),

                provider="AbuseIPDB"

            )

        except requests.RequestException:

            return None

        except KeyError:

            return None