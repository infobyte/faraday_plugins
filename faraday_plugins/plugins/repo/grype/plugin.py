"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import json
import re
from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.plugins_utils import VulnerabilitySeverity

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

        # One advisory commonly matches several artifacts of the same image, and
        # those matches share the host vulnerability identity (name + description).
        # The host vulnerability cache keeps only the first of them, so merge the
        # evidence here instead of losing every artifact but the first. Severity
        # filters are applied per match, before merging, so an excluded match
        # contributes neither artifact data nor references.
        groups = {}
        for match in grype_json['matches']:
            record = self.parse_match(match)
            if self._should_ignore_check({'severity': record['severity']}):
                continue
            key = (record['name'], record['description'])
            if key in groups:
                self.merge_matches(groups[key], record)
            else:
                groups[key] = record

        for record in groups.values():
            self.createAndAddVulnToHost(host_id,
                                        name=record['name'],
                                        desc=record['description'],
                                        ref=record['references'],
                                        severity=record['severity'],
                                        data="\n".join(record['artifacts']),
                                        cve=record['cve'])

    def parse_match(self, match):
        """Normalizes one Grype match into the fields of a host vulnerability."""
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
        severity = self.normalize_severity(severity)
        return {"name": name, "description": description, "cve": cve,
                "references": references, "severity": severity,
                "severity_level": VulnerabilitySeverity[severity.upper()].value,
                "artifacts": [data]}

    @staticmethod
    def merge_matches(target, record):
        """Merges a match with the same identity into the group's first record."""
        if record["severity_level"] > target["severity_level"]:
            target["severity"] = record["severity"]
            target["severity_level"] = record["severity_level"]
        for artifact in record["artifacts"]:
            if artifact not in target["artifacts"]:
                target["artifacts"].append(artifact)
        for reference in record["references"]:
            if reference not in target["references"]:
                target["references"].append(reference)

    def processCommandString(self, username, current_path, command_string):
        super().processCommandString(username, current_path, command_string)
        command_string += f" -o json --file {self._output_file_path}"
        return command_string


def createPlugin(*args, **kwargs):
    return GrypePlugin(*args, **kwargs)
