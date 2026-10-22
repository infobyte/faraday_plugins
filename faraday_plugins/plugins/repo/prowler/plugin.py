"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from dateutil.parser import parse
import csv
import io
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


def _split_pipe(value):
    return [item.strip() for item in (value or "").split("|") if item.strip()]


def parse_csv_records(output):
    """Convert Prowler CSV rows (semicolon separated) into Issue objects.

    Handles the v4+ column names (ACCOUNT_UID, RESOURCE_UID...) and the v3 ones
    (ACCOUNT_ID, RESOURCE_ARN...). Only FAIL rows are reported, like the JSON flavors.
    """
    if isinstance(output, bytes):
        output = output.decode("utf-8-sig", errors="replace")
    output = output.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(output), delimiter=";")
    issues = []
    for row in reader:
        if (row.get("STATUS") or "").strip().upper() != "FAIL":
            continue
        if (row.get("MUTED") or "").strip().lower() == "true":
            continue
        timestamp = row.get("TIMESTAMP") or row.get("ASSESSMENT_START_TIME")
        try:
            timestamp = parse(timestamp) if timestamp else None
        except (ValueError, TypeError, OverflowError):
            timestamp = None
        remediation = {"Recommendation": {"Text": row.get("REMEDIATION_RECOMMENDATION_TEXT", ""),
                                          "Url": row.get("REMEDIATION_RECOMMENDATION_URL", "")},
                       "Code": {"NativeIaC": row.get("REMEDIATION_CODE_NATIVEIAC", ""),
                                "Terraform": row.get("REMEDIATION_CODE_TERRAFORM", ""),
                                "CLI": row.get("REMEDIATION_CODE_CLI", ""),
                                "Other": row.get("REMEDIATION_CODE_OTHER", "")}}
        compliance = {}
        for item in _split_pipe(row.get("COMPLIANCE")):
            framework, _, controls = item.partition(":")
            compliance[framework.strip()] = [c.strip() for c in controls.split(",") if c.strip()]
        categories = [c.strip() for c in (row.get("CATEGORIES") or "").split(",") if c.strip()]
        resource_arn = row.get("RESOURCE_UID") or row.get("RESOURCE_ARN") or ""
        issues.append(Issue(
            region=row.get("REGION") or row.get("LOCATION") or "AWS_REGION",
            profile=row.get("AUTH_METHOD") or row.get("PROFILE") or "",
            severity=(row.get("SEVERITY") or "info").lower(),
            scored=row.get("STATUS", ""),
            account=row.get("ACCOUNT_UID") or row.get("ACCOUNT_ID") or "",
            description=row.get("DESCRIPTION", ""),
            status=row.get("STATUS", ""),
            status_extended=row.get("STATUS_EXTENDED", ""),
            check_title=row.get("CHECK_TITLE") or "Prowler finding",
            check_id=row.get("CHECK_ID", ""),
            timestamp=timestamp,
            compliance=compliance,
            categories=categories,
            service=row.get("SERVICE_NAME", ""),
            risk=row.get("RISK", ""),
            doc_link=row.get("RELATED_URL", ""),
            remediation=remediation,
            resource_arn=resource_arn,
            resource_id=row.get("RESOURCE_NAME") or row.get("RESOURCE_ID") or resource_arn,
        ))
    return issues


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
        self.extension = [".json", ".csv"]
        self.csv_headers = {"CHECK_ID", "STATUS", "SEVERITY", "PROVIDER"}

    def report_belongs_to(self, extension="", file_csv_headers=None, **kwargs):
        if extension == ".csv":
            return bool(file_csv_headers) and self.csv_headers.issubset(file_csv_headers)
        return super().report_belongs_to(extension=extension, **kwargs)

    def _is_ocsf(self, records):
        if not records:
            return False
        first = records[0] if isinstance(records, list) else records
        return isinstance(first, dict) and "finding_info" in first and "class_uid" in first

    def parseOutputString(self, output, debug=False):
        text = output.decode("utf-8-sig", errors="replace") if isinstance(output, bytes) else output
        if not text.lstrip("\ufeff").lstrip().startswith(("[", "{")):
            issues = parse_csv_records(text)
        else:
            records = json.loads(text)
            if self._is_ocsf(records):
                issues = [parse_ocsf_record(record) for record in records if record.get("status_code") == "FAIL"]
            else:
                issues = ProwlerJsonParser(text).issues

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
