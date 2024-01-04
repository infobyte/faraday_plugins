"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2023, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@faradaysec.com"
__status__ = "Development"

SCORE_KUBESCAPE_RANGE = [(0, 1, 'info'),
               (1, 4, 'low'),
               (4, 7, 'med'),
               (7, 9, 'high'),
               (9, 10.1, 'critical')]


class KubescapePlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Kubescape_JSON"
        self.name = "Kubescape Json"
        self.plugin_version = "1.0.0"
        self.version = "2.9"
        self.json_keys = {'clusterAPIServerInfo', 'generationTime', 'results'}
        self._use_temp_file = True
        self._temp_file_extension = "json"

    @staticmethod
    def get_severity_from_score(score):
        try:
            if not isinstance(score, float):
                score = float(score)

            for (lower, upper, severity) in SCORE_KUBESCAPE_RANGE:
                if lower <= score < upper:
                    return severity
        except ValueError:
            return 'unclassified'

    def parseOutputString(self, output):
        data = json.loads(output)
        resources_ids = {}
        for resource in data['resources']:
            object_data = resource["object"]
            if 'name' in object_data:
                name = object_data.get('name')
            else:
                name = object_data.get('metadata', {}).get('name')
            resources_ids[resource['resourceID']] = name
        controls = data['summaryDetails']['controls']
        for result in data['results']:
            for control in result['controls']:
                if not control.get('status', {}).get('status', '') == 'failed':
                    continue
                h_id = self.createAndAddHost(name=resources_ids[result['resourceID']])
                desc = 'Control\' Rules:\n'
                for rule in control['rules']:
                    desc += f'Rule Name: {rule["name"]}\n'
                    desc += f'Rule status: {rule["status"]}\n'
                    if 'paths' in rule:
                        desc += 'Paths:\n'
                        for path in rule.get('paths', []):
                            if 'failedPath' in path:
                                desc += f'Failed Path: {path["failedPath"]}\n'
                            if 'fixPath' in path:
                                desc += f'Fix Path: {path["fixPath"]["path"]}\n'
                                desc += f'Value: {path["fixPath"]["value"]}\n'
                severity = self.get_severity_from_score(
                    controls[control['controlID']]['scoreFactor']
                )
                self.createAndAddVulnToHost(
                    host_id=h_id,
                    name=control['name'],
                    desc=desc,
                    severity=severity,
                    external_id=control['controlID'],
                )


def createPlugin(*args, **kwargs):
    return KubescapePlugin(*args, **kwargs)
