from config.config_loader import ConfigLoader
from detection.base_detector import BaseDetector
from models.suspicious_event import SuspiciousEvent
from config.constants import Severity


class AWSDetector(BaseDetector):

    def __init__(self):

        rules = ConfigLoader.load_detection_rules()

        aws = rules["aws"]

        self.root_login = aws["root_login"]
        self.iam_user_creation = aws["iam_user_creation"]
        self.policy_change = aws["policy_change"]
        self.security_group_change = aws["security_group_change"]

    def analyze(self, events):

        detections = []

        if self.root_login["enabled"]:
            detections.extend(
                self._detect_root_login(events)
            )

        if self.iam_user_creation["enabled"]:
            detections.extend(
                self._detect_iam_user_creation(events)
            )

        if self.policy_change["enabled"]:
            detections.extend(
                self._detect_policy_change(events)
            )

        if self.security_group_change["enabled"]:
            detections.extend(
                self._detect_security_group_change(events)
            )

        return detections

    def _detect_root_login(self, events):

        detections = []

        for event in events:

            if (
                event.event_name == self.root_login["event_name"]
                and event.username.lower() == "root"
            ):

                detections.append(

                    SuspiciousEvent(

                        detection_name=self.root_login["name"],

                        severity=Severity[
                            self.root_login["severity"].upper()
                        ],

                        description="AWS Root account logged into the console.",

                        timestamp=event.timestamp,

                        source_ip=event.source_ip,

                        username=event.username,

                        affected_service="AWS IAM",

                        evidence=event.raw_log,

                        recommendation="Verify whether this login was expected."
                    )
                )

        return detections

    def _detect_iam_user_creation(self, events):

        detections = []

        for event in events:

            if event.event_name == self.iam_user_creation["event_name"]:

                detections.append(

                    SuspiciousEvent(

                        detection_name=self.iam_user_creation["name"],

                        severity=Severity[
                            self.iam_user_creation["severity"].upper()
                        ],

                        description=f"IAM user '{event.username}' was created.",

                        timestamp=event.timestamp,

                        source_ip=event.source_ip,

                        username=event.username,

                        affected_service="AWS IAM",

                        evidence=event.raw_log,

                        recommendation="Verify the IAM user creation."
                    )
                )

        return detections

    def _detect_policy_change(self, events):

        detections = []

        for event in events:

            if event.event_name == self.policy_change["event_name"]:

                detections.append(

                    SuspiciousEvent(

                        detection_name=self.policy_change["name"],

                        severity=Severity[
                            self.policy_change["severity"].upper()
                        ],

                        description="IAM policy was modified.",

                        timestamp=event.timestamp,

                        source_ip=event.source_ip,

                        username=event.username,

                        affected_service="AWS IAM",

                        evidence=event.raw_log,

                        recommendation="Review the policy modification."
                    )
                )

        return detections

    def _detect_security_group_change(self, events):

        detections = []

        for event in events:

            if event.event_name == self.security_group_change["event_name"]:

                detections.append(

                    SuspiciousEvent(

                        detection_name=self.security_group_change["name"],

                        severity=Severity[
                            self.security_group_change["severity"].upper()
                        ],

                        description="Security Group ingress rule changed.",

                        timestamp=event.timestamp,

                        source_ip=event.source_ip,

                        username=event.username,

                        affected_service="AWS EC2",

                        evidence=event.raw_log,

                        recommendation="Verify the security group modification."
                    )
                )

        return detections