"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat
from dateutil.parser import parse
from bs4 import BeautifulSoup

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
    'TO_REVIEW': 'open',
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
            creation_date = parse(issue['creationDate'])
            data = [] if not issue['flows'] else ["Flows:"]
            for flow in issue['flows']:
                for location in flow['locations']:
                    location_message = f"\"{location['msg']}\" in line {location['textRange']['startLine']} " \
                                       f"of {components[component]['longName']}"
                    data.append(location_message)
            vulns.append(
                {'name': message, 'desc': vuln_description, 'project': project, 'path': path, 'severity': severity, 'status': status, 'tags': tags,
                 'run_date': creation_date, 'data': "\n".join(data), 'external_id': external_id})
        for issue in json_data.get('hotspots', []):
            component = issue['component']['key']
            rule = issue['rule']
            if component not in components:
                components[component] = {
                    'longName': issue['component']['longName']
                }
            path = components[component]['longName']

            severity = rule['vulnerabilityProbability'].lower()
            name = rule['name']
            vuln_description = issue['message']
            project = f"Project: {issue['project']['key']}"
            status = STATUSES[issue['status']]
            tags = issue.get('tags')
            external_id = issue['rule']['key']
            creation_date = parse(issue['creationDate'])
            data = BeautifulSoup(f'''Risk Description: {rule["riskDescription"]}
            Vulnerability Description: {rule["vulnerabilityDescription"]}
            ''', features="lxml").get_text()
            resolution = BeautifulSoup(rule['fixRecommendations'], features="lxml").get_text()
            vulns.append(
                {
                    'name': name,
                    'desc': vuln_description,
                    'project': project,
                    'path': path,
                    'severity': severity,
                    'status': status,
                    'tags': tags,
                    'run_date': creation_date,
                    'data': data,
                    'external_id': external_id,
                    'resolution': resolution
                }
            )
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
            host_id = self.createAndAddHost(vuln.pop('path'), description=vuln.pop('project'))
            self.createAndAddVulnToHost(
                host_id=host_id,
                **vuln
            )


def createPlugin(*args, **kwargs):
    return SonarQubeAPIPlugin(*args, **kwargs)
