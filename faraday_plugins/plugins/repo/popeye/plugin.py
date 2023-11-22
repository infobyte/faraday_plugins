"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Faradaysec LLC"
__credits__ = ["Gonzalo Martinez"]
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@faradaysec.com"
__status__ = "Development"


class PopeyeJsonPlugin(PluginJsonFormat):
    map_level = {
        '1': 'low',
        '2': 'med',
        '3': 'high'
    }

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Popeye_Json"
        self.name = "Popeye JSON Output Plugin"
        self.plugin_version = "1"
        self.json_keys = {'popeye'}
        self.framework_version = "1.0.0"
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        data = json.loads(output)
        for test in data['popeye'].get('sanitizers'):
            path = test.get('gvr')
            sanitizer = test.get('sanitizer')
            h_id = False
            for issue in test.get('issues', []):
                for group in test['issues'][issue]:
                    level = group.get('level', 0)
                    if level == 0:
                        continue
                    if not h_id:
                        h_id = self.createAndAddHost(issue)
                    external_id = group.get("message").split(']')[0].replace('[', '')
                    desc = f'{group.get("message").split("]")[1]}\nPATH: {path}'
                    self.createAndAddVulnToHost(
                        host_id=h_id,
                        name=sanitizer,
                        desc=desc,
                        severity=self.map_level[str(level)],
                        external_id=external_id
                    )


def createPlugin(*args, **kwargs):
    return PopeyeJsonPlugin(*args, **kwargs)
