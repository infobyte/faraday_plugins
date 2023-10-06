"""
Faraday Penetration Test IDE
Copyright (C) 2023:https://www.faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
from faraday_plugins.plugins.plugin import PluginJsonFormat
import re
import requests

__author__ = "pastaoficial"
__copyright__ = "Copyright (c) 2023, FaradaySec LLC"
__credits__ = ["pastaoficial"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "pastaoficial"
__email__ = "jaguinaga@faradaysec.com"
__status__ = "Development"


class LeakIxPlugin(PluginJsonFormat):
    """
    Example plugin to parse leakix output.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "LeakIx"
        self.name = "LeakIx json importer"
        self.plugin_version = "0.0.1"
        self.version = "0.4.4.9-alpha"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self.target = None

        self.addSetting("api-key", str, "_jXAGogdIxei2Jxh2oorXMKCNjn_HqUlvOnooGPnvo9SEhtJ")

    def parseOutputString(self, output):
        """
        This method will discard the output the shell sends, it will read it from
        the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """
        headers = {
            'api-key': self.getSetting('api-key'),
            'Accept': 'application/json'
        }

        try:
            page = requests.get("https://leakix.net/search?scope=leak&q=gov.ar", headers=headers)
            data = page.json()
        except Exception:
            self.logger.info("[LeakIx] - Connection with api")
            return

        for vuln in data:
            desc = vuln['summary']
            desc += "\n\n"
            print(vuln.keys())
            not_before = vuln['ssl']['certificate']['not_before']
            not_after = vuln['ssl']['certificate']['not_after']
            #TODO: pasar a date y hacer la resta para ver cuantos dias hace que esta

            desc += "First seen {0}".format(not_before)
            desc += "\nLast seen {0}".format(not_after)

            h_id = self.createAndAddHost(vuln['host'])
            v_id = self.createAndAddVulnToHost(
                    h_id,
                    "LeakIX source {0}".format(vuln['event_source']),
                )

def createPlugin(*args, **kwargs):
    return LeakIxPlugin(*args, **kwargs)
