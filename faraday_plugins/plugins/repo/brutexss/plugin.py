"""
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re
from urllib.parse import urlparse

__author__ = "Roberto Focke"
__copyright__ = "Copyright (c) 2017, Infobyte LLC"
__license__ = ""
__version__ = "1.0.0"

from faraday_plugins.plugins.plugin import PluginBase
from faraday_plugins.plugins.plugins_utils import resolve_hostname


class brutexss (PluginBase):

    def __init__(self):
        super().__init__()
        self.id = "brutexss"
        self.name = "brutexss"
        self.plugin_version = "0.0.2"
        self.version = "1.0.0"
        self.protocol ='tcp'
        self._command_regex = re.compile(r'^(sudo brutexss|brutexss|sudo brutexss\.py|brutexss\.py|python brutexss\.py|'
                                         r'\.\/brutexss\.py)\s+.*?')

    def parseOutputString(self, output, debug=False):
        lineas = output.split("\n")
        parametro = []
        found_vuln = False
        for linea in lineas:
            if linea.find("is available! Good!") > 0:
                url = re.findall('(?:[-\w.]|(?:%[\da-fA-F]{2}))+', linea)[0]
                port = 80
                if urlparse(url).scheme == 'https':
                    port = 443
                netloc_splitted = urlparse(url).netloc.split(':')
                if len(netloc_splitted) > 1:
                    port = netloc_splitted[1]
            if linea.find("Vulnerable") > 0 and "No" not in linea:
                vuln_list = re.findall("\w+", linea)
                if vuln_list[2] == "Vulnerable":
                    parametro.append(vuln_list[1])
                    found_vuln=len(parametro) > 0
                    host_id = self.createAndAddHost(url)
                    address = resolve_hostname(url)
                    interface_id = self.createAndAddInterface(host_id, address, ipv4_address=address,
                                                              hostname_resolution=[url])
                    service_id = self.createAndAddServiceToInterface(host_id, interface_id, self.protocol, 'tcp',
                                                                     ports=[port], status='Open', version="",
                                                                     description="")
        if found_vuln:
            self.createAndAddVulnWebToService(host_id, service_id, name="xss", desc="XSS", ref='', severity='med',
                                              website=url, path='', method='', pname='', params=''.join(parametro),
                                              request='', response='')



def createPlugin():
    return brutexss()

# I'm Py3
