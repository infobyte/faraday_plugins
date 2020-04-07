"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re
import socket
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat
from urllib.parse import urlparse


__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class WhitesourceJsonParser:
    def __init__(self, json_output):
        self.json_data = json.loads(json_output)

    def parse_url(self, url):
        url_parse = urlparse(url)
        protocol = url_parse.scheme
        hostname = url_parse.netloc
        port = url_parse.port
        address = self.get_address(hostname)

        if port is None:
            return {'protocol': protocol, 'hostname': hostname, 'port': None, 'address': address}

        return {'protocol': protocol, 'hostname': hostname, 'port': [port], 'address': address}

    def get_address(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except socket.error as msg:
            return '0.0.0.0'


class WhitesourcePlugin(PluginJsonFormat):
    def __init__(self):
        super().__init__()
        self.id = "whitesource"
        self.name = "whitesource"
        self.plugin_version = "0.1"
        self.version = "3.4.5"
        self.json_keys = {"vulnerabilities"}

    def parseOutputString(self, output, debug=False):
        parser = WhitesourceJsonParser(output)
        if parser.json_data['vulnerabilities']:
            for whitesource in parser.json_data['vulnerabilities']:
                url_data = parser.parse_url(whitesource['url'])
                host_id = self.createAndAddHost(url_data['address'], hostnames=[url_data['hostname']],
                                                scan_template=whitesource['name'])
                service_id = self.createAndAddServiceToHost(host_id, "Apache", url_data['protocol'],
                                                            ports=url_data['port'], status='open', version='')

                if 'topFix' in whitesource:
                    self.createAndAddVulnWebToService(host_id, service_id, name=whitesource['name'],
                                                      desc=whitesource['description'],
                                                      resolution=whitesource['topFix']['fixResolution'],
                                                      ref=f"CVSS: {whitesource['score']} "
                                                          f"URL: { whitesource['topFix']['url']}",
                                                      category=whitesource['topFix']['type'],
                                                      data=whitesource['topFix']['message'],
                                                      severity=whitesource['severity'])
                else:
                    self.createAndAddVulnWebToService(host_id, service_id, name=whitesource['name'],
                                                      desc=whitesource['description'],
                                                      ref=f"CVSS: {whitesource['score']}",
                                                      severity=whitesource['severity'])




def createPlugin():
    return WhitesourcePlugin()

# I'm Py3