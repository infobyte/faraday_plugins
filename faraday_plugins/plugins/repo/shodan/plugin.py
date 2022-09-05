"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re
import json
import argparse
import shlex
import gzip
import os
import shutil

from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat
from faraday_plugins.plugins.plugins_utils import get_severity_from_cvss

__author__ = "Valentin Vila"
__copyright__ = "Copyright (c) 2021, Faraday"
__credits__ = ["Valentin Vila"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Valentin Vila"
__email__ = "vvila@faradaysec.com"
__status__ = "Development"


class ShodanPlugin(PluginMultiLineJsonFormat):
    """
    This plugin handles the Shodan tool.
    Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "shodan"
        self.name = "Shodan"
        self.plugin_version = "0.0.1"
        self.version = "1.0.0"
        self._command_regex = re.compile(r'^shodan\s+(?P<option>search|download)\s+.*\w+')
        self._use_temp_file = True
        self._temp_file_extension = "json.gz"
        self.json_keys = {'_shodan'}

    def _parse_filename(self, filename):
        if self.has_custom_output():
            with gzip.open(filename, 'rb') as output:
                self.parseOutputString(output.read().decode('utf-8'))
        else:
            with open(filename) as output:
                self.parseOutputString(output.read())
        if self._delete_temp_file:
            try:
                if os.path.isfile(filename):
                    os.remove(filename)
                elif os.path.isdir(filename):
                    shutil.rmtree(filename)
            except Exception as e:
                self.logger.error(f"Error on delete file: ({filename}) [{e}]")

    def parseOutputString(self, output):
        for vuln_json in filter(lambda x: x != '', output.split("\n")):
            vuln_dict = json.loads(vuln_json)
            ip = vuln_dict.get('ip_str')
            port = vuln_dict.get('port')
            vulns = vuln_dict.get('vulns')
            transport = vuln_dict.get('transport')
            hostnames = vuln_dict.get('hostnames')
            h_id = self.createAndAddHost(ip, hostnames=hostnames)
            s_id = self.createAndAddServiceToHost(h_id, "http", protocol=transport, ports=port)
            if vulns is not None:
                for name, vuln_info in vulns.items():
                    description = vuln_info.get('summary')
                    references = vuln_info.get('references')
                    self.createAndAddVulnToService(h_id, s_id, name, desc=description, ref=references
                                                   , cve=name)

    def processCommandString(self, username, current_path, command_string):
        """
        Adds the path to a temporary file parameter to get .json.gz output to the command string that the
        user has set.
        """
        super().processCommandString(username, current_path, command_string)
        parser = argparse.ArgumentParser(conflict_handler='resolve')
        match = self._command_regex.match(command_string)
        if match.groupdict()['option'] == 'search':
            parser.add_argument("--color", action="store_true")
            parser.add_argument("--no-color", action="store_true")
            parser.add_argument("--fields", type=str)
            parser.add_argument("--limit", type=int)
            parser.add_argument("--separator", type=str, nargs=-1)
            parser.add_argument("query")
        else:
            parser.add_argument("--limit", type=int)
            parser.add_argument("query", type=str, nargs=-1)
        args = parser.parse_args(shlex.split(command_string.split("search ")[-1]))
        limit = args.limit
        query = args.query
        cmd = "shodan download"
        if limit:
            cmd += f" --limit {limit}"
        cmd += f" {self._output_file_path} {query}"
        return cmd


def createPlugin(*args, **kwargs):
    return ShodanPlugin(*args, **kwargs)
