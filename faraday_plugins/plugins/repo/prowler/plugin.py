"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from dateutil.parser import parse
import json
from datetime import datetime
from dataclasses import dataclass
from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Diego Nadares"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Diego Nadares", "Nicolas Rebagliati"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Diego Nadares"
__email__ = "dnadares@faradaysec.com"
__status__ = "Development"


@dataclass
class Issue:
    region: str
    profile: str
    severity: str
    scored: str
    account: str
    description: str
    status: str
    status_extended: str
    check_title: str
    check_id: str
    timestamp: datetime
    compliance: str
    categories: str
    service: str
    risk: str
    doc_link: str
    remediation: str
    resource_arn: str
    resource_id: str


class ProwlerJsonParser:

    def parse_issues(self, records):
        records = json.loads(records)
        for record in records:
            region = record.get("Region", "AWS_REGION")
            profile = record.get("Profile", "")
            severity = record.get("Severity", "info").lower()
            scored = record.get("Status", "")
            account = record.get("AccountId", "")
            description = record.get("Description", "")
            status = record.get("Status", "")
            status_extended = record.get("StatusExtended", "")
            check_title = record.get("CheckTitle", "")
            check_id = record.get("CheckID", "")
            timestamp = record.get("AssessmentStartTime", None)
            if timestamp:
                timestamp = parse(timestamp)
            compliance = record.get("Compliance", "")
            categories = record.get("Categories", "")
            service = record.get("ServiceName", "")
            risk = record.get("Risk", "")
            doc_link = record.get("RelatedUrl", "")
            remediation = record.get("Remediation", "")
            resource_arn = record.get("ResourceArn", "")
            resource_id = record.get("ResourceId", "")
            if status == "FAIL":
                self.issues.append(Issue(region=region, profile=profile, severity=severity,
                                         scored=scored, categories=categories, account=account,
                                         description=description, status=status, status_extended=status_extended,
                                         check_title=check_title, check_id=check_id, timestamp=timestamp,
                                         compliance=compliance, service=service, risk=risk,
                                         doc_link=doc_link, remediation=remediation, resource_id=resource_id,
                                         resource_arn=resource_arn)
                                   )

    def __init__(self, json_output):
        self.issues = []
        self.parse_issues(json_output)


def parse_remediation(remediation):
    if not isinstance(remediation, dict):
        return str(remediation or "")

    if "desc" in remediation or "references" in remediation:
        # OCSF format (Prowler v4+)
        parts = [remediation.get("desc", "")]
        for url in remediation.get("references", []) or []:
            parts.append(url)
        return "\n".join(p for p in parts if p)

    # Legacy ASFF format (Prowler v3)
    resolution_text = ""
    resolution_url = ""
    NativeIaC = Terraform = CLI = Other = ""

    recommendation = remediation.get("Recommendation", None)
    if recommendation:
        resolution_text = recommendation.get("Text", "")
        resolution_url = recommendation.get("Url", "")

    code = remediation.get("Code", None)
    if code:
        NativeIaC = code.get("NativeIaC", "")
        Terraform = code.get("Terraform", "")
        CLI = code.get("CLI", "")
        Other = code.get("Other", "")

    resolution = f"{resolution_text}"
    if resolution_url:
        resolution = f"{resolution}\n{resolution_url}"
    if NativeIaC:
        resolution = f"{resolution}\n{NativeIaC}"
    if Terraform:
        resolution = f"{resolution}\n{Terraform}"
    if CLI:
        resolution = f"{resolution}\n{CLI}"
    if Other:
        resolution = f"{resolution}\n{Other}"

    return resolution


def parse_compliance(compliance: dict) -> list:
    compliance_str_list = []
    for key, value in compliance.items():
        for item in value:
            compliance_str_list.append(f"{key}:{item}")
    return compliance_str_list


def parse_ocsf_record(record):
    """Convert a single Prowler v4+ OCSF event into the Issue dataclass.

    OCSF emits status_code in {FAIL, PASS, MANUAL, ...}. We only surface FAILs
    as vulnerabilities. PASS and MANUAL findings are skipped (caller filters).
    """
    finding_info = record.get("finding_info", {}) or {}
    cloud = record.get("cloud", {}) or {}
    account = (cloud.get("account") or {}).get("uid", "")
    region = cloud.get("region", "AWS_REGION")
    resources = record.get("resources") or []
    first_resource = resources[0] if resources else {}
    unmapped = record.get("unmapped", {}) or {}

    timestamp = record.get("time_dt") or record.get("time")
    if isinstance(timestamp, (int, float)):
        try:
            timestamp = datetime.fromtimestamp(timestamp)
        except (ValueError, OSError):
            timestamp = None
    elif isinstance(timestamp, str):
        try:
            timestamp = parse(timestamp)
        except (ValueError, TypeError):
            timestamp = None

    return Issue(
        region=region,
        profile=cloud.get("provider", ""),
        severity=(record.get("severity") or "info").lower(),
        scored=record.get("status_code", ""),
        account=account,
        description=finding_info.get("desc", "") or finding_info.get("title", ""),
        status=record.get("status_code", ""),
        status_extended=record.get("status_detail", "") or record.get("message", ""),
        check_title=finding_info.get("title", "") or "Prowler finding",
        check_id=finding_info.get("uid", ""),
        timestamp=timestamp,
        compliance=unmapped.get("compliance", {}) or {},
        categories=unmapped.get("categories", []) or [],
        service=(record.get("metadata", {}) or {}).get("product", {}).get("feature", {}).get("name", ""),
        risk=record.get("risk_details", "") or unmapped.get("risk", ""),
        doc_link=unmapped.get("related_url", "") or "",
        remediation=record.get("remediation", {}) or {},
        resource_arn=first_resource.get("uid", ""),
        resource_id=first_resource.get("name", "") or first_resource.get("uid", ""),
    )


class ProwlerPlugin(PluginJsonFormat):
    """ Handle the AWS Prowler tool. Detects the output of the tool
    and adds the information to Faraday. Supports both legacy v3 JSON-ASFF
    and v4+ OCSF formats.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "prowler"
        self.name = "Prowler"
        self.plugin_version = "0.2"
        self.version = "0.0.2"
        self.json_keys = [
            {"Profile", "AccountId", "OrganizationsInfo", "Region"},
            {"finding_info", "class_uid", "severity_id", "status_code", "resources"},
        ]

    def _is_ocsf(self, records):
        if not records:
            return False
        first = records[0] if isinstance(records, list) else records
        return isinstance(first, dict) and "finding_info" in first and "class_uid" in first

    def parseOutputString(self, output, debug=False):
        records = json.loads(output)
        issues = []
        if self._is_ocsf(records):
            for record in records:
                if record.get("status_code") != "FAIL":
                    continue
                issues.append(parse_ocsf_record(record))
        else:
            parser = ProwlerJsonParser(output)
            issues = parser.issues

        for issue in issues:
            host_name = f"{issue.resource_id}"
            host_id = self.createAndAddHost(name=host_name,
                                            description=f"AWS Service: {issue.service} "
                                                        f"- Account: {issue.account} "
                                                        f"- Region: {issue.region}\n"
                                                        f"ARN: {issue.resource_arn}")

            vuln_desc = f"{issue.description}\n{issue.risk}"
            resolution = parse_remediation(issue.remediation) if isinstance(issue.remediation, dict) else str(issue.remediation or "")
            compliance_violations = parse_compliance(issue.compliance) if isinstance(issue.compliance, dict) else []
            tags = issue.categories if isinstance(issue.categories, list) else (
                [issue.categories] if issue.categories else []
            )
            self.createAndAddVulnToHost(
                host_id=host_id,
                name=issue.check_title,
                desc=vuln_desc,
                data=f"{issue.status_extended}",
                severity=self.normalize_severity(issue.severity),
                resolution=resolution,
                run_date=issue.timestamp,
                external_id=f"{self.name.upper()}-{issue.check_id}",
                ref=[issue.doc_link] if issue.doc_link else [],
                policyviolations=compliance_violations,
                tags=tags,
            )


def createPlugin(*args, **kwargs):
    return ProwlerPlugin(*args, **kwargs)
