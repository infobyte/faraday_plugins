"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""

import xml.etree.ElementTree as ET

from faraday_plugins.plugins.plugin import PluginXMLFormat

__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "1.0"
__maintainer__ = "Blas Moyano"
__status__ = "Development"


class NcrackParser:
    def __init__(self, xml_output):
        self.tree = self.parse_xml(xml_output)
        if self.tree:
            scanner = self.tree.attrib.get('scanner', None)
            args = self.tree.attrib.get('args', None)
            start = self.tree.attrib.get('start', None)
            start_str = self.tree.attrib.get('start_str', None)
            service_data = None if self.tree.find('service') is None else \
                self.get_service(self.tree.findall('service'))
            self.ncrack_info = {
                "scanner_name": scanner,
                "args": args,
                "date": start,
                "date_str": start_str,
                "info_service": service_data
            }
        else:
            self.tree = None

    def parse_xml(self, xml_output):
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError as err:
            print(f'SyntaxError In xml: {err}. {xml_output}')
            return None
        return tree

    def get_service(self, tree):
        list_service_info = []
        for service in tree:
            address = service.find('address')
            port = service.find('port')
            credential = service.find('credentials')
            if address is not None:
                addr = address.attrib.get('addr', None)
                addr_type = address.attrib.get('addrtype', None)
            else:
                addr = None
                addr_type = None

            if port is not None:
                protocol = port.attrib.get('protocol', None)
                port_number = port.attrib.get('portid', None)
                port_name = port.attrib.get('name', None)
            else:
                protocol = None
                port_number = None
                port_name = None

            if credential is not None:
                user = credential.attrib.get('username', None)
                passw = credential.attrib.get('password', None)
            else:
                user = None
                passw = None

            service_info = {
                "addr": addr,
                "addr_type": addr_type,
                "protocol": protocol,
                "port_number": port_number,
                "port_name": port_name,
                "user": user,
                "passw": passw
            }
            list_service_info.append(service_info)
        return list_service_info


class NcrackPlugin(PluginXMLFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "ncrackrun"
        self.id = 'ncrack'
        self.name = 'ncrack XML Plugin'
        self.plugin_version = '0.0.1'
        self.version = '1.0.0'
        self.framework_version = '1.0.0'

    def parseOutputString(self, output):
        parser = NcrackParser(output)
        data = parser.ncrack_info

        for service_vuln in data['info_service']:
            host_id = self.createAndAddHost(service_vuln['addr'],
                                            description=f"{data['scanner_name']} - args: {data['args']}")

            service_id = self.createAndAddServiceToHost(host_id,
                                                        service_vuln['addr'],
                                                        ports=service_vuln['port_number'],
                                                        protocol=service_vuln['protocol'],
                                                        description=service_vuln['port_name'])
            if service_vuln['user'] is not None or service_vuln['passw'] is not None:
                self.createAndAddCredToService(host_id,
                                               service_id,
                                               username=service_vuln['user'],
                                               password=service_vuln['passw'])


def createPlugin(*args, **kwargs):
    return NcrackPlugin(*args, **kwargs)
