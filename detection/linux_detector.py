from collections import defaultdict

from config.config_loader import ConfigLoader
from config.constants import LoginStatus

from detection.base_detector import BaseDetector
from models.suspicious_event import SuspiciousEvent
from config.constants import Severity

def parse_severity(value: str):

    return Severity[value.upper()]


class LinuxDetector(BaseDetector):

    def __init__(self):

        config = ConfigLoader.load_detection_rules()

        linux = config["linux"]

        self.brute_force = linux["brute_force"]
        self.password_spray = linux["password_spray"]
        self.privilege_escalation = linux["privilege_escalation"]

    def analyze(self, events):

        detections = []

        if self.brute_force["enabled"]:
            detections.extend(
                self._detect_bruteforce(events)
            )

        if self.password_spray["enabled"]:
            detections.extend(
                self._detect_password_spray(events)
            )

        if self.privilege_escalation["enabled"]:
            detections.extend(
                self._detect_privilege_escalation(events)
            )

        return detections

    def _detect_bruteforce(self, events):

        detections = []

        failed_by_ip = defaultdict(list)

        for event in events:

            if event.status == LoginStatus.FAILED:
                failed_by_ip[event.source_ip].append(event)

        for ip, attempts in failed_by_ip.items():

            attempts.sort(key=lambda e: e.timestamp)

            threshold = self.brute_force["max_failed_logins"]

            if len(attempts) >= threshold:

                first = attempts[0]
                last = attempts[-1]

                duration = (
                    last.timestamp - first.timestamp
                ).total_seconds()

                window = self.brute_force["time_window_seconds"]

                if duration <= window:

                    detections.append(
                        SuspiciousEvent(
                            detection_name=self.brute_force["name"],
                            severity=parse_severity(
                                self.brute_force["severity"]
                            ),
                            description=(
                                f"{len(attempts)} failed SSH logins "
                                f"from {ip}"
                            ),
                            timestamp=last.timestamp,
                            source_ip=ip,
                            username=None,
                            affected_service="SSH",
                            evidence=attempts,
                            recommendation=self.brute_force["recommendation"],
                        )
                    )

        return detections


    def _detect_password_spray(self, events):

        detections = []

        usernames = defaultdict(set)

        timestamps = {}

        for event in events:

            if event.status == LoginStatus.FAILED:

                usernames[event.source_ip].add(
                    event.username
                )

                timestamps[event.source_ip] = event.timestamp

        for ip, users in usernames.items():

            threshold = self.password_spray[
                "unique_accounts_threshold"
            ]

            if len(users) >= threshold:


                detections.append(
                    SuspiciousEvent(
                        detection_name=self.password_spray["name"],
                        severity=parse_severity(
                            self.password_spray["severity"]
                        ),
                        description=(
                            f"{ip} attempted "
                            f"{len(users)} usernames."
                        ),
                        timestamp=timestamps[ip],
                        source_ip=ip,
                        username=None,
                        affected_service="SSH",
                        evidence=list(users),
                        recommendation=self.password_spray["recommendation"],
                    )
                )

        return detections

    def _detect_privilege_escalation(self, events):

        detections = []

        for event in events:

            privileged_users = self.privilege_escalation[
                "privileged_users"
            ]

            if (
                event.status == LoginStatus.SUCCESS
                and event.username in privileged_users
            ):

                detections.append(
                    SuspiciousEvent(
                        detection_name=self.privilege_escalation["name"],
                        severity=parse_severity(
                            self.privilege_escalation["severity"]
                        ),
                        description=self.privilege_escalation["description"],
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        username="root",
                        affected_service="SSH",
                        evidence=event.raw_log,
                        recommendation=self.privilege_escalation["recommendation"],
                    )
                )

        return detections