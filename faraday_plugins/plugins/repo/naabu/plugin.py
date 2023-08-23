"""
Faraday Plugins
Copyright (c) 2021 Faraday Security LLC (https://www.faradaysec.com/)
See the file 'doc/LICENSE' for the license information

"""
import socket
import json
import re
from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat

__author__ = 'Emilio Couto'
__copyright__ = 'Copyright (c) 2021, Faraday Security LLC'
__credits__ = ['Emilio Couto']
__license__ = ''
__version__ = '0.0.1'
__maintainer__ = 'Emilio Couto'
__email__ = 'ecouto@faradaysec.com'
__status__ = 'Development'


class NaabuPlugin(PluginMultiLineJsonFormat):
    """
    Parse Naabu (from Project Discovery) scanner JSON output
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = 'naabu'
        self.name = 'Naabu'
        self.plugin_version = '0.1'
        self.version = '2.0.3'
        self.json_keys = {'host', 'ip', 'port'}
        self._command_regex = re.compile(r'^(sudo naabu|naabu|\.\/nmap)\s+.*?')

    def parseOutputString(self, output, debug=False):
        for host_json in filter(lambda x: x != '', output.split('\n')):
            host_dict = json.loads(host_json)
            host = host_dict.get('host')
            ip = host_dict.get('ip')
            port = host_dict.get('port')
            try:
                if isinstance(port, dict):
                    port = port.get("Port")
                service = socket.getservbyport(port)
            except OSError:
                service = 'Unknown service on port ' + str(port)
            host_id = self.createAndAddHost(
                name=ip,
                hostnames=[host])
            self.createAndAddServiceToHost(
                host_id,
                name=service,
                ports=port,
                protocol='tcp',
                status='open',
                version='',
                description='')

    def processCommandString(self, username, current_path, command_string):
        """
        Adds the -oX parameter to get xml output to the command string that the
        user has set.
        """
        super().processCommandString(username, current_path, command_string)
        if " -json" not in command_string:
            command_string += " -json"
        if " -silent" not in command_string:
            command_string += " -silent"
        return command_string

def createPlugin(*args, **kwargs):
    return NaabuPlugin(*args, **kwargs)
