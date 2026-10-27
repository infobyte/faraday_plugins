"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import json
import re
from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Joachim Bauernberger"
__license__ = "MIT"
__version__ = "1.0.0"
__maintainer__ = "Joachim Bauernberger"
__email__ = "joachim.bauernberger@protonmail.com"
__status__ = "Development"


class GrypePlugin(PluginJsonFormat):
    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = 'grype'
        self.name = 'Grype JSON Plugin'
        self.plugin_version = '1.0.0'
        self._command_regex = re.compile(r'^grype\s+.*')
        self._use_temp_file = True
        self._temp_file_extension = "json"
        self.json_keys = [{"source", "matches", "descriptor"}, {"matches", "image"}]

    def parseOutputString(self, output, debug=True):
        grype_json = json.loads(output)
        if "userInput" in grype_json.get("source", {"target": ""}).get("target"):
            name = grype_json["source"]["target"]["userInput"]
            host_type = grype_json['source']['type']
        elif "tags" in grype_json.get("image", {}):
            name = " ".join(grype_json["image"]["tags"])
            host_type = "Docker Image"
        else:
            name = grype_json["source"]["target"]
            host_type = grype_json['source']['type']
        host_id = self.createAndAddHost(name, description=f"Type: {host_type}")
        for match in grype_json['matches']:
            name = match.get('vulnerability').get('id')
            cve = name
            references = []
            if match.get("relatedVulnerabilities"):
                description = match["relatedVulnerabilities"][0].get('description')
                references.append(match["relatedVulnerabilities"][0]["dataSource"])
                related_vuln = match["relatedVulnerabilities"][0]
                severity = related_vuln["severity"].lower().replace("negligible", "info")
                if related_vuln.get("links"):
                    for url in related_vuln["links"]:
                        references.append(url)
                else:
                    for url in related_vuln["urls"]:
                        references.append(url)
            else:
                description = match.get('vulnerability').get('description', "Issues provided no description")
                severity = match.get('vulnerability').get('severity').lower().replace("negligible", "info")
                if match.get('vulnerability').get("links"):
                    for url in match.get('vulnerability')["links"]:
                        references.append(url)
                else:
                    for url in match.get('vulnerability')["urls"]:
                        references.append(url)
            if not match['artifact'].get('metadata'):
                data = f"Artifact: {match['artifact']['name']}" \
                       f"Version: {match['artifact']['version']} " \
                       f"Type: {match['artifact']['type']}"
            else:
                if "Source" in match['artifact']['metadata']:
                    data = f"Artifact: {match['artifact']['name']} [{match['artifact']['metadata']['Source']}] " \
                           f"Version: {match['artifact']['version']} " \
                           f"Type: {match['artifact']['type']}"
                elif "VirtualPath" in match['artifact']['metadata']:
                    data = f"Artifact: {match['artifact']['name']} [{match['artifact']['metadata']['VirtualPath']}] " \
                           f"Version: {match['artifact']['version']} " \
                           f"Type: {match['artifact']['type']}"
                else:
                    data = f"Artifact: {match['artifact']['name']}" \
                           f"Version: {match['artifact']['version']} " \
                           f"Type: {match['artifact']['type']}"
            cvss3 = {}
            cvss2 = {}
            cvss4 = {}
            cvss_list = match.get('vulnerability', {}).get('cvss') or []
            if not cvss_list and match.get('relatedVulnerabilities'):
                cvss_list = match['relatedVulnerabilities'][0].get('cvss') or []
            for c in cvss_list:
                v_str = c.get('vector')
                base = (c.get('metrics') or {}).get('baseScore')
                if c.get('version', '').startswith('4') and not cvss4:
                    cvss4 = {'vector_string': v_str, 'base_score': base}
                elif c.get('version', '').startswith('3') and not cvss3:
                    cvss3 = {'vector_string': v_str, 'base_score': base}
                elif c.get('version', '').startswith('2') and not cvss2:
                    cvss2 = {'vector_string': v_str, 'base_score': base}

            cwe = []
            cwe_list = match.get('vulnerability', {}).get('cwes') or []
            if not cwe_list and match.get('relatedVulnerabilities'):
                cwe_list = match['relatedVulnerabilities'][0].get('cwes') or []
            for c in cwe_list:
                cid = c.get('cwe') if isinstance(c, dict) else c
                if cid and cid not in cwe:
                    cwe.append(cid)

            self.createAndAddVulnToHost(host_id,
                                        name=name,
                                        desc=description,
                                        ref=references,
                                        severity=severity,
                                        data=data,
                                        cve=cve,
                                        cwe=cwe,
                                        cvss2=cvss2,
                                        cvss3=cvss3,
                                        cvss4=cvss4)

    def processCommandString(self, username, current_path, command_string):
        super().processCommandString(username, current_path, command_string)
        command_string += f" -o json --file {self._output_file_path}"
        return command_string


def createPlugin(*args, **kwargs):
    return GrypePlugin(*args, **kwargs)
