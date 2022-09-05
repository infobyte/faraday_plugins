"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re
import os

from faraday_plugins.plugins.plugin import PluginBase


__author__ = "Javier Victor Mariano Bruno"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Javier Victor Mariano Bruno"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Javier Victor Mariano Bruno"
__email__ = "mbruno@infobytesec.com"
__status__ = "Development"


class CmdFtpPlugin(PluginBase):
    """
    This plugin handles ftp command.
    Basically detects if user was able to connect to a device
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "ftp"
        self.name = "Ftp"
        self.plugin_version = "0.0.1"
        self.version = "0.17"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(r'^ftp\s+.*?')
        self._host_ip = None
        self._port = "21"
        self._info = 0
        self._version = None



    def parseOutputString(self, output):

        host_info = re.search(r"Connected to (.+)\.", output)
        banner = re.search(r"220?([\w\W]+)$", output)
        if re.search("Connection timed out", output) is None and host_info is not None:
            hostname = host_info.group(1)
            ip_address = self.resolve_hostname(hostname)
            self._version = banner.groups(0) if banner else ""
            h_id = self.createAndAddHost(ip_address, hostnames=[hostname])
            s_id = self.createAndAddServiceToHost(
                h_id,
                "ftp",
                "tcp",
                ports=[self._port],
                status="open")
        return True

    def processCommandString(self, username, current_path, command_string):
        """
        """
        super().processCommandString(username, current_path, command_string)
        count_args = command_string.split()
        c = count_args.__len__()
        self._port = "21"
        if re.search(r"[\d]+", count_args[c - 1]):
            self._port = count_args[c - 1]


def createPlugin(*args, **kwargs):
    return CmdFtpPlugin(*args, **kwargs)
