"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import socket
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat


__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class AwsProwlerJsonParser:

    def __init__(self, json_output):
        string_manipulate = json_output.replace("}", "},")
        json_manipulate = string_manipulate[:len(string_manipulate) - 2]
        json_bla = "{%s}" % json_manipulate

        self.json_data = json.loads(json_bla)

    def get_address(self, hostname):
        # Returns remote IP address from hostname.
        try:
            return socket.gethostbyname(hostname)
        except socket.error as msg:
            return '0.0.0.0'


class AwsProwlerPlugin(PluginJsonFormat):
    """ Handle the AWS Prowler tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self):
        super().__init__()
        self.id = "awsprowler"
        self.name = "AWS Prowler"
        self.plugin_version = "0.1"
        self.version = "0.0.1"
        self.json_keys = {""}

    def parseOutputString(self, output, debug=False):
        parser = AwsProwlerJsonParser(output)
        print(parser)

def createPlugin():
    return AwsProwlerPlugin()
