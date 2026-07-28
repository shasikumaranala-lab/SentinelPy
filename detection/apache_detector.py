from detection.base_detector import BaseDetector
from config.constants import Severity
from models.suspicious_event import SuspiciousEvent
from config.config_loader import ConfigLoader


class ApacheDetector(BaseDetector):

    SQLI_PATTERNS = (
        "union select",
        "' or ",
        "\" or ",
        "--",
        "drop table",
        "insert into",
        "update ",
        "delete from",
        "sleep(",
        "benchmark(",
    )

    XSS_PATTERNS = (
        "<script",
        "%3cscript",
        "javascript:",
        "onerror=",
        "onload=",
        "alert(",
    )

    TRAVERSAL_PATTERNS = (
        "../",
        "..\\",
        "%2e%2e",
        "..%2f",
        "..%5c",
        "/etc/passwd",
        "system32",
    )

    SCANNERS = (
        "sqlmap",
        "nikto",
        "burp",
        "curl",
        "wget",
        "python-requests",
        "go-http-client",
    )

    def __init__(self):

        rules = ConfigLoader.load_detection_rules()

        apache = rules["apache"]

        self.sql_injection = apache["sql_injection"]
        self.xss = apache["xss"]
        self.directory_traversal = apache["directory_traversal"]
        self.scanner_detection = apache["scanner_detection"]

    def analyze(self, events):

        detections = []

        if self.sql_injection["enabled"]:
            detections.extend(
                self._detect_sql_injection(events)
            )

        if self.xss["enabled"]:
            detections.extend(
                self._detect_xss(events)
            )

        if self.directory_traversal["enabled"]:
            detections.extend(
                self._detect_directory_traversal(events)
            )

        if self.scanner_detection["enabled"]:
            detections.extend(
                self._detect_scanners(events)
            )

        return detections


    def _detect_sql_injection(self, events):

        detections = []

        for event in events:

            url = event.url.lower()

            patterns = self.sql_injection["patterns"]

            for pattern in patterns:

                if pattern in url:

                    detections.append(
                        SuspiciousEvent(
                            detection_name=self.sql_injection["name"],
                            severity=Severity[
                                self.sql_injection["severity"].upper()
                            ],
                            description=f"Detected SQL Injection pattern '{pattern}'",
                            timestamp=event.timestamp,
                            source_ip=event.client_ip,
                            username=None,
                            affected_service="Apache",
                            evidence=event.raw_log,
                            recommendation=self.sql_injection["recommendation"]
                        )
                    )

                    break

        return detections

    def _detect_xss(self, events):

        detections = []

        for event in events:

            url = event.url.lower()

            patterns = self.xss["patterns"]

            for pattern in patterns:

                if pattern in url:

                    detections.append(
                        SuspiciousEvent(
                            detection_name=self.xss["name"],
                            severity=Severity[
                                self.xss["severity"].upper()
                            ],
                            description=f"Detected XSS pattern: {pattern}",
                            timestamp=event.timestamp,
                            source_ip=event.client_ip,
                            username=None,
                            affected_service="Apache",
                            evidence=event.raw_log,
                            recommendation=self.xss["recommendation"],
                        )
                    )

                    break

        return detections

    def _detect_directory_traversal(self, events):

        detections = []

        for event in events:

            url = event.url.lower()

            patterns = self.directory_traversal["patterns"]

            for pattern in patterns:

                if pattern in url:

                    detections.append(
                        SuspiciousEvent(
                            detection_name=self.directory_traversal["name"],
                            severity=Severity[
                                self.directory_traversal["severity"].upper()
                            ],
                            description=f"Detected directory traversal pattern: {pattern}",
                            timestamp=event.timestamp,
                            source_ip=event.client_ip,
                            username=None,
                            affected_service="Apache",
                            evidence=event.raw_log,
                            recommendation=self.directory_traversal["recommendation"],
                        )
                    )

                    break

        return detections

    def _detect_scanners(self, events):

        detections = []

        for event in events:

            agent = (event.user_agent or "").lower()

            for scanner in self.SCANNERS:

                if scanner in agent:

                    detections.append(
                        SuspiciousEvent(
                            detection_name="Scanner Detected",
                            severity=Severity.MEDIUM,
                            description=f"Scanner '{scanner}' detected.",
                            timestamp=event.timestamp,
                            source_ip=event.client_ip,
                            username=None,
                            affected_service="Apache",
                            evidence=event.user_agent,
                            recommendation="Review activity.",
                        )
                    )

                    break

        return detections