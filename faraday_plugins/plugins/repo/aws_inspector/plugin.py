"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file "doc/LICENSE" for the license information

"""
from faraday_plugins.plugins.plugin import PluginJsonFormat
from json import loads

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"


class AWSInspectorJsonPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "AWSInspector_Json"
        self.name = "AWS Inspector JSON Output Plugin"
        self.plugin_version = "1"
        self.version = "9"
        self.json_keys = {"findings"}
        self.framework_version = "1.0.0"
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        # Useful docs about aws finding struct: https://docs.aws.amazon.com/inspector/v2/APIReference/API_Finding.html
        data = loads(output)
        for finding in data["findings"]:
            cve = []
            refs = []
            cvss2 = {}
            cvss3 = {}
            status = finding.get("status", "ACTIVE")

            # AWS possible status are ACTIVE | SUPPRESSED | CLOSED
            if status != 'ACTIVE':
                continue

            name = finding.get("title", "")
            description = finding.get("description", "")
            severity = finding.get('severity', 'unclassified').lower().replace("untriaged", "unclassified")

            vulnerability_details = finding.get("packageVulnerabilityDetails")
            if vulnerability_details:
                cve = vulnerability_details.get("vulnerabilityId", None)
                if cve != name:
                    name = name.replace(f"{cve} - ", "")

                refs = vulnerability_details.get("referenceUrls", [])
                source_url = vulnerability_details.get("sourceUrl", "")
                if isinstance(source_url, str):
                    refs.append(source_url)
                elif isinstance(source_url, list):
                    refs += source_url

            if "inspectorScoreDetails" in finding and "adjustedCvss" in finding["inspectorScoreDetails"]:
                version = finding["inspectorScoreDetails"]["adjustedCvss"].get("version")
                if version:
                    vector_string = finding["inspectorScoreDetails"]["adjustedCvss"]["scoringVector"]
                    if "3" in version:
                        cvss3 = {
                            "vector_string": vector_string
                        }
                    elif "2" in version:
                        cvss2 = {
                            "vector_string": vector_string
                        }

            vulnerability = {
                "name": name,
                "desc": description,
                "ref": refs,
                "severity": severity,
                "cve": cve,
                "cvss2": cvss2,
                "cvss3": cvss3,
            }

            for resource in finding.get("resources", []):
                resource_name = f"{finding.get('awsAccountId', '')} | {resource.get('id', '')}"
                hostnames = []
                resource_details = resource.get("details", {})
                if "awsEc2Instance" in resource_details:
                    for hostname in resource_details["awsEc2Instance"].get("ipV4Addresses", []):
                        hostnames.append(hostname)

                host_id = self.createAndAddHost(
                    name=resource_name,
                    hostnames=hostnames
                )
                self.createAndAddVulnToHost(
                    host_id=host_id,
                    **vulnerability
                )


def createPlugin(*args, **kwargs):
    return AWSInspectorJsonPlugin(*args, **kwargs)
