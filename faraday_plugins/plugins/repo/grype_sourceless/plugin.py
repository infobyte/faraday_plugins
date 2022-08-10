"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import json
import re
from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Gonzalo Martinez"
__license__ = "MIT"
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytsec.com"
__status__ = "Development"


class GrypePlugin(PluginJsonFormat):
    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = 'grype_sourceless'
        self.name = 'Grype Sourceless JSON Plugin'
        self.plugin_version = '1.0.0'
        self._command_regex = re.compile(r'^grype_sourceless\s+.*')
        self._use_temp_file = True
        self._temp_file_extension = "json"
        self.json_keys = {"matches", "image"}

    def parseOutputString(self, output, debug=True):
        grype_json = json.loads(output)
        name = " ".join(grype_json["image"]["tags"])
        host_id = self.createAndAddHost(name, description="Type: Docker Image")
        for match in grype_json['matches']:
            name = match.get('vulnerability').get('id')
            cve = name
            references = []
            if match.get("relatedVulnerabilities"):
                description = match["relatedVulnerabilities"][0].get('description')
                references.append(match["relatedVulnerabilities"][0]["dataSource"])
                related_vuln = match["relatedVulnerabilities"][0]
                severity = related_vuln["severity"].lower().replace("negligible", "info")
                for url in related_vuln["links"]:
                    references.append(url)
            else:
                description = match.get('vulnerability').get('description', "Issues provided no description")
                severity = match.get('vulnerability').get('severity').lower().replace("negligible", "info")
                for link in match.get('vulnerability').get('links'):
                    references.append(link)
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
            self.createAndAddVulnToHost(host_id,
                                        name=name,
                                        desc=description,
                                        ref=references,
                                        severity=severity,
                                        data=data,
                                        cve=cve)

    def processCommandString(self, username, current_path, command_string):
        super().processCommandString(username, current_path, command_string)
        command_string += f" -o json --file {self._output_file_path}"
        return command_string


def createPlugin(ignore_info=False, hostname_resolution=True):
    return GrypePlugin(ignore_info=ignore_info, hostname_resolution=hostname_resolution)
