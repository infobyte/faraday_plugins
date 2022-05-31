"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat
from datetime import datetime
import dateutil

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
    'CONFIRMED': 'open',
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
        components = {item['key']:
                          {'name': item['name'], 'longName': item['longName']}
                      for item in json_data['components'] }
        for issue in json_data['issues']:
            if issue['type'] != VULNERABILITY:
                continue

            component = issue['component']
            path = components[component]['longName']
            vuln_description = f"Issue found in line {issue['line']} of {path}"
            project = f"Project: {issue['project']}"
            severity = SEVERITIES[issue['severity']]
            message = issue['message']
            status = STATUSES[issue['status']]
            tags = issue['tags']
            external_id = issue['rule']
            creation_date = dateutil.parser.parse(issue['creationDate'])
            data = [] if not issue['flows'] else ["Flows:"]
            for flow in issue['flows']:
                for location in flow['locations']:
                    location_message = f"\"{location['msg']}\" in line {location['textRange']['startLine']} " \
                                       f"of {components[component]['longName']}"
                    data.append(location_message)
            vulns.append(
                {'name': message, 'description': vuln_description, 'project': project, 'path': path, 'severity': severity, 'status': status, 'tags': tags,
                 'creation_date': creation_date, 'data': "\n".join(data), 'external_id': external_id})

        return vulns


class SonarQubeAPIPlugin(PluginJsonFormat):
    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.json_keys = {'total', 'effortTotal', 'issues', 'components', 'facets'}
        self.id = "sonarqubeAPI"
        self.name = "SonarQube API Plugin"
        self.plugin_version = "0.0.1"


    def parseOutputString(self, output, debug=False):
        parser = SonarQubeAPIParser(output)
        for vuln in parser.vulns:
            host_id = self.createAndAddHost(vuln['path'], description=vuln['project'])

            self.createAndAddVulnToHost(
                host_id=host_id,
                name=vuln['name'],
                desc=vuln['description'],
                status=vuln['status'],
                run_date=vuln['creation_date'],
                severity=vuln['severity'],
                tags=vuln['tags'],
                data=vuln['data'],
                external_id=vuln['external_id']
            )


def createPlugin(ignore_info=False, hostname_resolution=True):
    return SonarQubeAPIPlugin(ignore_info=ignore_info, hostname_resolution=hostname_resolution)
