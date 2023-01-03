"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""

from faraday_plugins.plugins.plugin import PluginXMLFormat
from faraday_plugins.plugins.plugins_utils import CVE_regex, CWE_regex
from xml.etree import ElementTree as ET

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"


class CisPlugin(PluginXMLFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.ns = {
            "scap-con": "{http://scap.nist.gov/schema/scap/constructs/1.2}",
            "arf": "{http://scap.nist.gov/schema/asset-reporting-format/1.1}",
            "dsc": "{http://scap.nist.gov/schema/scap/source/1.2}",
            "ai": "{http://scap.nist.gov/schema/asset-identification/1.1}",
            "xccdf": "{http://checklists.nist.gov/xccdf/1.2}"
        }
        self.identifier_tag = "asset-report-collection"
        self.id = "CIS"
        self.name = "CIS XML Output Plugin"
        self.plugin_version = "1.0.0"

    def parseOutputString(self, output):

        root = ET.fromstring(output)
        rules = {}
        for rule in root.findall(f".//{self.ns['xccdf']}Rule"):
            rules[rule.attrib['id']] = {
                "title": rule[0].text,
                "description": rule[1][0].text
            }
        reports = root.findall(f".//{self.ns['arf']}reports")
        for report in reports:
            target_address = report.find(f".//{self.ns['xccdf']}target-address").text
            rules_results = report.findall(f".//{self.ns['xccdf']}rule-result")
            h_id = self.createAndAddHost(target_address)
            for rule_result in rules_results:
                result = rule_result.find(f"{self.ns['xccdf']}result").text
                if result != "pass":
                    severity = rule_result.attrib.get("severity","unclassified")
                    rule_id = rule_result.attrib['idref']
                    references = []
                    for ident in rule_result.findall(f"{self.ns['xccdf']}ident"):
                        text = ident.text
                        if isinstance(text, str) and len(text) > 10:
                            references.append(text)
                    self.createAndAddVulnToHost(
                        h_id,
                        name=rules[rule_id]["title"],
                        desc=rules[rule_id]["description"],
                        severity=severity,
                        ref=references
                    )

def createPlugin(*args, **kwargs):
    return CisPlugin(*args, **kwargs)
