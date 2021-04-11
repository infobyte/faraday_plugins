"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from faraday_plugins.plugins.plugin import PluginBase
import re


__author__ = "Federico Kirschbaum"
__copyright__ = "Copyright 2011, Faraday Project"
__credits__ = ["Federico Kirschbaum"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Federico Kirschbaum"
__email__ = "fedek@infobytesec.com"
__status__ = "Development"


class CmdPropeciaPlugin(PluginBase):
    """
    This plugin handles propecia command.
    Basically inserts into the tree the ouput of this tool
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "propecia"
        self.name = "propecia port scanner"
        self.plugin_version = "0.0.1"
        self.version = "1.0"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(
            r'^(sudo propecia|\.\/propecia|propecia)\s+.*?')
        self._host_ip = None
        self._port = "23"

    def parseOutputString(self, output):

        host_info = re.search(
            r"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)", output)

        if host_info is None:
            self.logger.info("No hosts detected")
        else:
            for host in output.splitlines():
                if host != "":
                    h_id = self.createAndAddHost(host)
                    s_id = self.createAndAddServiceToHost(h_id, str(self._port), "tcp", ports=[self._port],
                                                          status="open", version="", description="")
        return True

    def processCommandString(self, username, current_path, command_string):
        super().processCommandString(username, current_path, command_string)
        count_args = command_string.split()

        if count_args.__len__() == 3:
            self._port = count_args[2]


def createPlugin(ignore_info=False):
    return CmdPropeciaPlugin(ignore_info=ignore_info)


