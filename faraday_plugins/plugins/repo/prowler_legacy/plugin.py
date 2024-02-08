"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from dateutil.parser import parse
import re
import json
from datetime import datetime
from dataclasses import dataclass
from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat

__author__ = "Nicolas Rebagliati"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Nicolas Rebagliati"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Nicolas Rebagliati"
__email__ = "nrebagliati@faradaysec.com"
__status__ = "Development"
CHECK_NUMBER_REGEX = re.compile(r"^(\[check\d\])")

@dataclass
class Issue:
    region: str
    profile: str
    severity: str
    scored: str
    account: str
    message: str
    control: str
    status: str
    level: str
    control_id: str
    timestamp: datetime
    compliance: str
    service: str
    caf_epic: str
    risk: str
    doc_link: str
    remediation: str
    resource_id: str


class ProwlerJsonParser:

    def parse_issues(self, records):
        for record in records:
            json_data = json.loads(record)
            region = json_data.get("Region", "AWS_REGION")
            profile = json_data.get("Profile", "")
            severity = json_data.get("Severity", "info").lower()
            scored = json_data.get("Status", "")
            account = json_data.get("Account Number", "")
            message = json_data.get("Message", "")
            control = CHECK_NUMBER_REGEX.sub("", json_data.get("Control", "")).strip()
            status = json_data.get("Status", "")
            level = json_data.get("Level", "")
            control_id = json_data.get("Control ID", "")
            timestamp = json_data.get("Timestamp", None)
            if timestamp:
                timestamp = parse(timestamp)
            compliance = json_data.get("Compliance", "")
            service = json_data.get("Service", "")
            caf_epic = [json_data.get("CAF Epic", "")]
            risk = json_data.get("Risk", "")
            doc_link = json_data.get("Doc link", "")
            remediation = json_data.get("Remediation", "")
            resource_id = json_data.get("Resource ID", "")
            if status == "FAIL":
                self.issues.append(Issue(region=region, profile=profile, severity=severity, scored=scored,
                                         account=account, message=message, control=control, status=status,
                                         level=level, control_id=control_id, timestamp=timestamp, compliance=compliance,
                                         service=service, caf_epic=caf_epic, risk=risk, doc_link=doc_link,
                                         remediation=remediation, resource_id=resource_id))

    def __init__(self, json_output):
        self.issues = []
        self.parse_issues(json_output.splitlines())


class ProwlerLegacyPlugin(PluginMultiLineJsonFormat):
    """ Handle the AWS Prowler tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "prowler_legacy"
        self.name = "Prowler"
        self.plugin_version = "0.1"
        self.version = "0.0.1"
        self.json_keys = {"Profile", "Account Number", "Region"}

    def parseOutputString(self, output, debug=False):
        parser = ProwlerJsonParser(output)
        for issue in parser.issues:
            host_name = f"{issue.service}-{issue.account}-{issue.region}"
            host_id = self.createAndAddHost(name=host_name,
                                            description=f"AWS Service: {issue.service} - Account: {issue.account}"
                                                        f" - Region: {issue.region}")

            vuln_desc = f"{issue.risk}\nCompliance: {issue.compliance}\nMessage: {issue.message}"
            self.createAndAddVulnToHost(host_id=host_id, name=issue.control, desc=vuln_desc,
                                        data=f"Resource ID: {issue.resource_id}",
                                        severity=self.normalize_severity(issue.severity), resolution=issue.remediation,
                                        run_date=issue.timestamp, external_id=f"{self.name.upper()}-{issue.control_id}",
                                        ref=[issue.doc_link],
                                        policyviolations=issue.caf_epic)


def createPlugin(*args, **kwargs):
    return ProwlerLegacyPlugin(*args, **kwargs)
