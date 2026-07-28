from collections import defaultdict

from config.config_loader import ConfigLoader
from config.constants import LoginStatus, Severity
from detection.base_detector import BaseDetector
from models.suspicious_event import SuspiciousEvent


class WindowsDetector(BaseDetector):

    def __init__(self):

        rules = ConfigLoader.load_detection_rules()

        windows = rules["windows"]

        self.failed_login = windows["failed_login"]
        self.account_lockout = windows["account_lockout"]
        self.new_user_creation = windows["new_user_creation"]
        self.privilege_group_change = windows["privilege_group_change"]

    def analyze(self, events):

        detections = []

        if self.failed_login["enabled"]:
            detections.extend(
                self._detect_failed_login_burst(events)
            )

        if self.account_lockout["enabled"]:
            detections.extend(
                self._detect_account_lockout(events)
            )

        if self.new_user_creation["enabled"]:
            detections.extend(
                self._detect_new_user(events)
            )

        if self.privilege_group_change["enabled"]:
            detections.extend(
                self._detect_group_change(events)
            )

        return detections

    def _detect_failed_login_burst(self, events):

        detections = []

        failed_by_ip = defaultdict(list)

        for event in events:

            if event.status == LoginStatus.FAILED:
                failed_by_ip[event.source_ip].append(event)

        threshold = self.failed_login["max_failed_logins"]
        window = self.failed_login["time_window_seconds"]

        for ip, attempts in failed_by_ip.items():

            attempts.sort(key=lambda e: e.timestamp)

            if len(attempts) < threshold:
                continue

            duration = (
                attempts[-1].timestamp -
                attempts[0].timestamp
            ).total_seconds()

            if duration <= window:

                detections.append(
                    SuspiciousEvent(
                        detection_name=self.failed_login["name"],
                        severity=Severity[self.failed_login["severity"].upper()],
                        description=(
                            f"{len(attempts)} failed Windows logins from {ip}"
                        ),
                        timestamp=attempts[-1].timestamp,
                        source_ip=ip,
                        username=None,
                        affected_service="Windows Logon",
                        evidence=attempts,
                        recommendation=self.failed_login["recommendation"]
                    )
                )

        return detections

    def _detect_account_lockout(self, events):

        detections = []

        for event in events:

            if getattr(event, "event_id", None) == 4740:

                detections.append(
                    SuspiciousEvent(
                        detection_name=self.account_lockout["name"],
                        severity=Severity[
                            self.account_lockout["severity"].upper()
                        ],
                        description=f"Account '{event.username}' locked.",
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        username=event.username,
                        affected_service="Windows",
                        evidence=event.raw_log,
                        recommendation=self.account_lockout["recommendation"]
                    )
                )

        return detections

    def _detect_new_user(self, events):

        detections = []

        for event in events:

            if getattr(event, "event_id", None) == 4720:

                detections.append(
                    SuspiciousEvent(
                        detection_name=self.new_user_creation["name"],
                        severity=Severity[
                            self.new_user_creation["severity"].upper()
                        ],
                        description=f"New user '{event.username}' created.",
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        username=event.username,
                        affected_service="Windows",
                        evidence=event.raw_log,
                        recommendation=self.new_user_creation["recommendation"]
                    )
                )

        return detections

    def _detect_group_change(self, events):

        detections = []

        for event in events:

            if getattr(event, "event_id", None) in (4728, 4732):
                detections.append(
                    SuspiciousEvent(
                        detection_name=self.privilege_group_change["name"],
                        severity=Severity[
                            self.privilege_group_change["severity"].upper()
                        ],
                        description=(
                            f"User '{event.username}' added to a privileged group."
                        ),
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        username=event.username,
                        affected_service="Windows",
                        evidence=event.raw_log,
                        recommendation=self.privilege_group_change["recommendation"]
                    )
                )

        return detections