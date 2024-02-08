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


class ProwlerPlugin(PluginJsonFormat):
    """ Handle the AWS Prowler tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "prowler"
        self.name = "Prowler"
        self.plugin_version = "0.1"
        self.version = "0.0.1"
        self.json_keys = {"Profile", "AccountId", "OrganizationsInfo", "Region"}

    def parseOutputString(self, output, debug=False):
        parser = ProwlerJsonParser(output)
        for issue in parser.issues:
            host_name = f"{issue.resource_id}"
            host_id = self.createAndAddHost(name=host_name,
                                            description=f"AWS Service: {issue.service} "
                                                        f"- Account: {issue.account} "
                                                        f"- Region: {issue.region}\n"
                                                        f"ARN: {issue.resource_arn}")

            vuln_desc = f"{issue.description}\n{issue.risk}"
            resolution = parse_remediation(issue.remediation)
            self.createAndAddVulnToHost(
                host_id=host_id,
                name=issue.check_title,
                desc=vuln_desc,
                data=f"{issue.status_extended}",
                severity=self.normalize_severity(issue.severity),
                resolution=resolution,
                run_date=issue.timestamp,
                external_id=f"{self.name.upper()}-{issue.check_id}",
                ref=[issue.doc_link],
                policyviolations=parse_compliance(issue.compliance),
                tags=issue.categories,
            )


def createPlugin(*args, **kwargs):
    return ProwlerPlugin(*args, **kwargs)
