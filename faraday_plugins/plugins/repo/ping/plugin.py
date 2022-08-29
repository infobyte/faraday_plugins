"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re

from faraday_plugins.plugins.plugin import PluginBase

__author__ = "Facundo de Guzmán, Esteban Guillardoy"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Facundo de Guzmán", "Esteban Guillardoy"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__ = "famato@infobytesec.com"
__status__ = "Development"


class CmdPingPlugin(PluginBase):
    """
    This plugin handles ping command.
    Basically detects if user was able to connect to a device
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "ping"
        self.name = "Ping"
        self.plugin_version = "0.0.1"
        self.version = "1.0.0"
        self._command_regex = re.compile(r'^(sudo ping|ping|sudo ping6|ping6)\s+.*?')

    def parseOutputString(self, output):

        reg = re.search(r"PING ([\w\.-:]+)( |)\(([\w\.:]+)\)", output)
        if re.search("0 received|unknown host", output) is None and reg is not None:
            ip_address = reg.group(3)
            hostname = reg.group(1)
            self.createAndAddHost(ip_address, hostnames=[hostname])
        return True

    def _isIPV4(self, ip):
        if len(ip.split(".")) == 4:
            return True
        else:
            return False


def createPlugin(*args, **kwargs):
    return CmdPingPlugin(*args, **kwargs)
