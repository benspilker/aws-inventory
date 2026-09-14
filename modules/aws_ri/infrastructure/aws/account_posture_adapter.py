"""Best-effort account posture collection through read-only AWS APIs."""

import logging
import json
from urllib.parse import unquote
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from aws_ri.domain.posture.account_posture import PostureRecord, AccountPostureSummary

logger = logging.getLogger(__name__)


class AccountPostureAdapter:
    """Collect security-service posture for one account."""

    def __init__(self, session: boto3.Session, account_id: str, regions: list[str]):
        self.session = session
        self.account_id = account_id
        self.regions = regions
        self.collection_status: dict[str, str] = {}

    def fetch(self) -> AccountPostureSummary:
        records: list[PostureRecord] = []
        records += self._config_compliance()
        records += self._guardduty()
        records += self._inspector()
        records += self._macie()
        records += self._access_analyzer()
        records += self._iam_credentials()
        records += self._backup()
        records += self._firewall_manager()
        records += self._shield()
        records += self._cloudtrail()
        records += self._s3_exposure()
        records += self._iam_policy_risk()
        return AccountPostureSummary(records)

    def _shield(self) -> list[PostureRecord]:
        try:
            client = self.session.client("shield", region_name="us-east-1")
            state = client.get_subscription_state().get("SubscriptionState", "NOT_SUBSCRIBED")
            result = [PostureRecord("Shield", self.account_id, state, title="Shield subscription", details={"subscription_state": state})]
            result += [PostureRecord("Shield", p.get("Id", ""), "PROTECTED", resource=p.get("ResourceArn", ""), title="Protection", details=p)
                       for page in client.get_paginator("list_protections").paginate() for p in page.get("Protections", [])]
            self._status("Shield", "Collected")
            return result
        except Exception as exc:
            self._record_error("Shield", exc)
            return []

    def _cloudtrail(self) -> list[PostureRecord]:
        try:
            client = self.session.client("cloudtrail", region_name="us-east-1")
            trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
            result = []
            for trail in trails:
                status = client.get_trail_status(Name=trail.get("TrailARN") or trail.get("Name"))
                details = {**trail, "trail_status": status}
                state = "LOGGING" if status.get("IsLogging") else "NOT_LOGGING"
                result.append(PostureRecord("CloudTrail", trail.get("TrailARN", trail.get("Name", "")), state,
                                            region="global", title=trail.get("Name", "Trail"), details=details))
            self._status("CloudTrail", "Collected" if trails else "No resources")
            return result
        except Exception as exc:
            self._record_error("CloudTrail", exc)
            return []

    def _s3_exposure(self) -> list[PostureRecord]:
        result = []
        try:
            client = self.session.client("s3", region_name="us-east-1")
            buckets = client.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket.get("Name", "")
                details = {}
                for label, operation in (("public_access_block", lambda: client.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})),
                                         ("policy_status", lambda: client.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})),
                                         ("encryption", lambda: client.get_bucket_encryption(Bucket=name).get("ServerSideEncryptionConfiguration", {}))):
                    try:
                        details[label] = operation()
                    except ClientError as exc:
                        details[label] = {"status": exc.response.get("Error", {}).get("Code", "Unavailable")}
                block = details.get("public_access_block", {})
                policy = details.get("policy_status", {})
                exposure = "PUBLIC" if policy.get("IsPublic") is True or (block and not all(block.get(k, False) for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"))) else ("NOT_PUBLIC" if block or policy else "UNKNOWN")
                result.append(PostureRecord("S3 public exposure", name, exposure, region="global",
                                            resource=f"arn:aws:s3:::{name}", title="Bucket exposure", details=details))
            self._status("S3 public exposure", "Collected" if buckets else "No resources")
            return result
        except Exception as exc:
            self._record_error("S3 public exposure", exc)
            return []

    def _iam_policy_risk(self) -> list[PostureRecord]:
        result = []
        try:
            client = self.session.client("iam", region_name="us-east-1")
            for page in client.get_paginator("list_policies").paginate(Scope="Local", OnlyAttached=True):
                for policy in page.get("Policies", []):
                    version = client.get_policy_version(PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]).get("PolicyVersion", {}).get("Document", {})
                    if isinstance(version, str):
                        version = json.loads(unquote(version))
                    statements = version.get("Statement", []) if isinstance(version, dict) else []
                    if isinstance(statements, dict):
                        statements = [statements]
                    for statement in statements:
                        actions = statement.get("Action", [])
                        resources = statement.get("Resource", [])
                        actions = actions if isinstance(actions, list) else [actions]
                        resources = resources if isinstance(resources, list) else [resources]
                        if "*" in actions or "*" in resources or statement.get("NotAction"):
                            result.append(PostureRecord("IAM policy risk", policy["Arn"], "HIGH", resource=policy.get("PolicyName", ""),
                                                        title="Wildcard or broad IAM statement", details={"statement": statement}))
            self._status("IAM policy risk", "Collected" if result else "No resources")
            return result
        except Exception as exc:
            self._record_error("IAM policy risk", exc)
            return []

    def _config_compliance(self) -> list[PostureRecord]:
        result: list[PostureRecord] = []
        for region in self.regions:
            try:
                client = self.session.client("config", region_name=region)
                recorder = client.describe_configuration_recorder_status()
                for page in client.get_paginator("describe_compliance_by_config_rule").paginate():
                    result += [PostureRecord("AWS Config compliance", r.get("ConfigRuleName", ""), r.get("Compliance", {}).get("ComplianceType", ""), region=region, title="Config rule", details=r) for r in page.get("ComplianceByConfigRules", [])]
                self._status("AWS Config compliance", "Collected" if result or recorder.get("ConfigurationRecordersStatus") else "No resources")
            except Exception as exc:
                self._record_error("AWS Config compliance", exc)
        return result

    def _guardduty(self) -> list[PostureRecord]:
        result: list[PostureRecord] = []
        for region in self.regions:
            client = self.session.client("guardduty", region_name=region)
            try:
                detectors = client.list_detectors().get("DetectorIds", [])
                if not detectors:
                    self._status("GuardDuty", "No resources")
                    continue
                for detector_id in detectors:
                    detector = client.get_detector(DetectorId=detector_id)
                    result.append(PostureRecord("GuardDuty", detector_id, detector.get("Status", ""), region=region, title="Detector", details=detector))
                    finding_ids = client.list_findings(DetectorId=detector_id).get("FindingIds", [])
                    if finding_ids:
                        findings = client.get_findings(DetectorId=detector_id, FindingIds=finding_ids).get("Findings", [])
                        result += [PostureRecord("GuardDuty", f.get("Id", ""), f.get("Severity", ""), region=region, resource=f.get("Resource", {}).get("ResourceId", ""), title=f.get("Title", ""), details=f) for f in findings]
                self._status("GuardDuty", "Collected")
            except Exception as exc:
                self._record_error("GuardDuty", exc)
        return result

    def _inspector(self) -> list[PostureRecord]:
        result: list[PostureRecord] = []
        for region in self.regions:
            try:
                client = self.session.client("inspector2", region_name=region)
                status = client.batch_get_account_status().get("accounts", [])
                result += [PostureRecord("Inspector", self.account_id, a.get("status", {}).get("statusCode", ""), region=region, title="Account status", details=a) for a in status]
                finding_arns = []
                for page in client.get_paginator("list_findings").paginate():
                    finding_arns += page.get("findingArns", [])
                for start in range(0, len(finding_arns), 10):
                    findings = client.batch_get_findings(findingArns=finding_arns[start:start + 10]).get("findings", [])
                    result += [PostureRecord("Inspector", f.get("findingArn", ""), f.get("severity", ""), region=region, resource=f.get("resources", [{}])[0].get("id", ""), title=f.get("title", ""), details=f) for f in findings]
                self._status("Inspector", "Collected" if result else "No resources")
            except Exception as exc:
                self._record_error("Inspector", exc)
        return result

    def _macie(self) -> list[PostureRecord]:
        result: list[PostureRecord] = []
        try:
            client = self.session.client("macie2", region_name=self.session.region_name or "us-east-1")
            data = client.get_macie_session()
            result.append(PostureRecord("Macie", self.account_id, data.get("status", ""), title="Macie session", details=data))
            self._status("Macie", "Collected")
        except Exception as exc:
            self._record_error("Macie", exc)
        return result

    def _access_analyzer(self) -> list[PostureRecord]:
        result: list[PostureRecord] = []
        for region in self.regions:
            try:
                client = self.session.client("accessanalyzer", region_name=region)
                analyzers = []
                for page in client.get_paginator("list_analyzers").paginate():
                    analyzers += page.get("analyzers", [])
                for analyzer in analyzers:
                    name = analyzer.get("name", "")
                    result.append(PostureRecord("Access Analyzer", name, analyzer.get("status", ""), region=region, title="Analyzer", details=analyzer))
                    for page in client.get_paginator("list_findings").paginate(analyzerArn=analyzer.get("arn")):
                        result += [PostureRecord("Access Analyzer", f.get("id", ""), f.get("status", ""), region=region, resource=f.get("resource", ""), title=f.get("resourceType", ""), details=f) for f in page.get("findings", [])]
                self._status("Access Analyzer", "Collected" if analyzers else "No resources")
            except Exception as exc:
                self._record_error("Access Analyzer", exc)
        return result

    def _iam_credentials(self) -> list[PostureRecord]:
        result: list[PostureRecord] = []
        try:
            client = self.session.client("iam", region_name=self.session.region_name or "us-east-1")
            for page in client.get_paginator("list_users").paginate():
                for user in page.get("Users", []):
                    user_name = user.get("UserName", "")
                    keys = client.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
                    for key in keys:
                        last_used = client.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                        result.append(PostureRecord("IAM credentials", key["AccessKeyId"], key.get("Status", ""), resource=user_name, title="Access key", details={"key": key, "last_used": last_used}))
            self._status("IAM credentials", "Collected" if result else "No resources")
        except Exception as exc:
            self._record_error("IAM credentials", exc)
        return result

    def _backup(self) -> list[PostureRecord]:
        result: list[PostureRecord] = []
        for region in self.regions:
            try:
                client = self.session.client("backup", region_name=region)
                for page in client.get_paginator("list_backup_plans").paginate():
                    result += [PostureRecord("Backup compliance", p.get("BackupPlanId", ""), "ENABLED", region=region, title=p.get("BackupPlanName", ""), details=p) for p in page.get("BackupPlansList", [])]
                protected = client.list_protected_resources().get("Results", [])
                result += [PostureRecord("Backup compliance", p.get("ResourceArn", ""), "PROTECTED", region=region, resource=p.get("ResourceArn", ""), title="Protected resource", details=p) for p in protected]
                self._status("Backup compliance", "Collected" if result else "No resources")
            except Exception as exc:
                self._record_error("Backup compliance", exc)
        return result

    def _firewall_manager(self) -> list[PostureRecord]:
        result: list[PostureRecord] = []
        try:
            client = self.session.client("fms", region_name=self.session.region_name or "us-east-1")
            for page in client.get_paginator("list_policies").paginate():
                result += [PostureRecord("Firewall Manager", p.get("PolicyId", ""), p.get("RemediationEnabled", ""), title=p.get("PolicyName", ""), details=p) for p in page.get("PolicyList", [])]
            self._status("Firewall Manager", "Collected" if result else "No resources")
        except Exception as exc:
            self._record_error("Firewall Manager", exc)
        return result

    def _status(self, label: str, status: str) -> None:
        if self.collection_status.get(label) == "Collected":
            return
        self.collection_status[label] = status

    def _record_error(self, label: str, exc: Exception) -> None:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        status = "Denied" if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError"} else "Unavailable"
        self._status(label, status)
        logger.warning("Skipping %s posture collection: %s", label, exc)
