"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re
import json
from faraday_plugins.plugins.plugin import PluginBase


__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class CmdNextNetin(PluginBase):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "nextnet"
        self.name = "nextnet"
        self.plugin_version = "0.0.1"
        self.version = "5.0.20"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(r'^[.]*?[/]*?nextnet\s+.*?')
        self._host_ip = None
        self._info = 0

    def parseOutputString(self, output):
        output_lines = output.split('\n')
        output_lines = output_lines[:-1]

        for line in output_lines:
            json_line = json.loads(line)
            info_data = json_line.get("info", None)
            desc = ""
            mac = None
            if info_data is not None:
                desc = f'Domain Tag: {info_data.get("domain", "Not tag info")}'
                mac = info_data.get("hwaddr")

            h_id = self.createAndAddHost(
                json_line.get("host", "0.0.0.0"),
                os=json_line.get("name", "unknown"),
                hostnames=json_line.get("nets"),
                mac=mac
            )
            self.createAndAddServiceToHost(
                h_id,
                name=json_line.get("probe", "unknown"),
                protocol=json_line.get("proto", "tcp"),
                ports=json_line.get("port", None),
                description=desc
            )
        return True


def createPlugin(*args, **kwargs):
    return CmdNextNetin(*args, **kwargs)
