from models.threat_intel import ThreatIntel


class ThreatCache:

    def __init__(self):

        self._cache: dict[str, ThreatIntel] = {}

    def get(self, ip_address: str) -> ThreatIntel | None:

        return self._cache.get(ip_address)

    def put(
        self,
        ip_address: str,
        threat_intel: ThreatIntel
    ) -> None:

        self._cache[ip_address] = threat_intel

    def contains(self, ip_address: str) -> bool:

        return ip_address in self._cache

    def clear(self) -> None:

        self._cache.clear()

    def size(self) -> int:

        return len(self._cache)