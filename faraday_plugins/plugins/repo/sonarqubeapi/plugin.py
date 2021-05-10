"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat
from datetime import datetime

VULNERABILITY = "VULNERABILITY"

# ATTENTION: The following mappings are created following the common sense in order to integrate F! with SQ. You
# can see what term means in the following website: https://docs.sonarqube.org/latest/user-guide/issues/
SEVERITIES = {
    'INFO': 'unclassified',
    'MINOR': 'low',
    'MAJOR': 'medium',
    'CRITICAL': 'high',
    'BLOCKER': 'critical'
}
STATUSES = {
    'OPEN': 'open',
    'CONFIRMED': 'opened',
    'REOPENED': 're-opened',
    'CLOSED': 'closed',
    'RESOLVED': 'closed'
}


class SonarQubeAPIParser:
    def __init__(self, json_output):
        json_data = json.loads(json_output)

        self.vulns = self._parse_vulns(json_data)

    def _parse_vulns(self, json_data):
        vulns = []

        for issue in json_data['issues']:
            if issue['type'] != VULNERABILITY:
                continue

            name = issue['rule']
            path = issue['component']
            severity = SEVERITIES[issue['severity']]
            message = issue['message']
            status = STATUSES[issue['status']]
            tags = issue['tags']
            creation_date = datetime.strptime(issue['creationDate'], '%Y-%m-%dT%H:%M:%S%z')

            vulns.append(
                {'name': name, 'path': path, 'message': message, 'severity': severity, "status": status, 'tags': tags,
                 'creation_date': creation_date})

        return vulns


class SonarQubeAPIPlugin(PluginJsonFormat):
    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "sonarqube-api"
        self.id = "SonarQubeAPI"
        self.name = "SonarQube API Plugin"
        self.plugin_version = "0.0.1"

    def report_belongs_to(self, **kwargs):
        if super().report_belongs_to(**kwargs):
            report_path = kwargs.get("report_path", "")
            with open(report_path) as f:
                output = f.read()
                json_data = json.loads(output)

                has_total = json_data.get('total', None) is not None
                has_p = json_data.get('p', None) is not None
                has_ps = json_data.get('ps', None) is not None
                has_paging = json_data.get('paging', None) is not None
                has_effort_total = json_data.get('effortTotal', None) is not None
                has_issues = json_data.get('issues', None) is not None
                has_components = json_data.get('components', None) is not None
                has_facets = json_data.get('facets', None) is not None

                return has_total and has_p and has_ps and has_paging and has_effort_total and has_issues and has_components and has_facets

        return False

    def parseOutputString(self, output, debug=False):
        parser = SonarQubeAPIParser(output)
        for vuln in parser.vulns:
            host_id = self.createAndAddHost(vuln['path'])

            self.createAndAddVulnToHost(
                host_id=host_id,
                name=vuln['name'],
                desc=vuln['message'],
                status=vuln['status'],
                run_date=vuln['creation_date'],
                severity=vuln['severity'],
                tags=vuln['tags']
            )


def createPlugin(ignore_info=False):
    return SonarQubeAPIPlugin(ignore_info=ignore_info)
