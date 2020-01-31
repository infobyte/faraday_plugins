#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from faraday_plugins.plugins.plugin import PluginXMLFormat
import socket
import random
import re
from urllib.parse import urlparse
import os

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

__author__ = 'Blas Moyano'
__copyright__ = 'Copyright 2020, Faraday Project'
__credits__ = ['Blas Moyano']
__license__ = ''
__version__ = '1.0.0'
__status__ = 'Development'


class CheckmarxXmlParser:
    def __init__(self, xml_output):
        self.tree = self.parse_xml(xml_output)
        if self.tree:
            self.cx_xml_results_attribs = self.tree.attrib
            self.query = self.getQuery(self.tree)
        else:
            self.query = None

    def parse_xml(self, xml_output):
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError as err:
            print('SyntaxError In xml: %s. %s' % (err, xml_output))
            return None
        return tree

    def getQuery(self, tree):
        for self.query_node in tree:
            yield Querys(self.query_node)


class Querys():
    def __init__(self, query_node):

        self.query_attrib = query_node.attrib
        self.result, self.path, self.path_node = self.get_Result(query_node.findall('Result'))

    def get_Result(self, result):
        result_atr = []
        path = []
        path_node = []
        for r in result:
            self.result_attrib = r.attrib
            self.path_attrib = r.find('Path').attrib
            self.path_node = self.get_path_node_info(r.find('Path').findall('PathNode'))
            result_atr.append(self.result_attrib)
            path.append(self.path_attrib)
            path_node.append(self.path_node)
        return result_atr, path, path_node

    def get_path_node_info(self, path_node):
        lista = []
        for pn in path_node:
            lista_v = []
            for info_pn in pn:
                if info_pn.tag == 'Snippet':
                    valor = (
                    'Number', info_pn.find('Line').find('Number').text, 'Code', info_pn.find('Line').find('Code').text)
                else:
                    valor = (info_pn.tag, info_pn.text)
                lista_v.append(valor)
            lista.append(lista_v)
        return lista


class CheckmarxPlugin(PluginXMLFormat):
    def __init__(self):
        super().__init__()
        self.identifier_tag = ["report", "CxXMLResults"]
        self.id = 'Checkmarx'
        self.name = 'Checkmarx XML Output Plugin'
        self.plugin_version = '1.0.0'
        self.version = '1.0.0'
        self.framework_version = '1.0.0'
        self.options = None
        self._command_regex = re.compile(r'^(checkmarx |\.\/checkmarx).*?')
        self.protocol = None
        self.hostname = None
        self.port = '80'
        self.address = None

    def parseOutputString(self, output):
        parser = CheckmarxXmlParser(output)

        if not parser.query:
            print('Error in xml report... Exiting...')
            return

        deeplink_check = 'categories' in parser.cx_xml_results_attribs

        if deeplink_check:
            url = urlparse(parser.cx_xml_results_attribs['DeepLink'])
            project_name = 'ProjectName' in parser.cx_xml_results_attribs
            if project_name:
                host_id = self.createAndAddHost(self.address, hostnames=[url.netloc],
                                                scan_template=parser.cx_xml_results_attribs['ProjectName'])
                interface_id = self.createAndAddInterface(host_id, self.address, ipv4_address=self.address,
                                                          hostname_resolution=[url.netloc])
                service_to_host = self.createAndAddServiceToHost(host_id, name=url.netloc, protocol=url.scheme,
                                                                  ports=url.port)

                service_to_interface = self.createAndAddServiceToInterface(host_id, interface_id, name=url.scheme,
                                                                           ports=url.port)

            else:
                host_id = self.createAndAddHost(self.address, hostnames=[url.netloc])

                interface_id = self.createAndAddInterface(host_id, self.address, ipv4_address=self.address,
                                                          hostname_resolution=[url.netloc])
                service_to_host = self.createAndAddServiceToHost(host_id, name=url.scheme, ports=url.port)

                service_to_interface = self.createAndAddServiceToInterface(host_id, interface_id, name=url.scheme,
                                                                           ports=url.port)

            for vulns in parser.query:

                categories = 'categories' in vulns.query_attrib
                if categories:
                    self.vuln_desc = vulns.query_attrib['categories']
                else:
                    self.vuln_desc = None
                self.vuln_name = vulns.query_attrib['name']
                self.vuln_severity = vulns.query_attrib['Severity']
                self.vuln_scan_id = vulns.query_attrib['cweId']
                self.resolution = vulns.path_node
                self.website = []
                self.pathfile = []
                for v_result in vulns.result:
                    self.website.append(v_result['DeepLink'])
                    self.pathfile.append(v_result['FileName'])

                self.createAndAddVulnToHost(host_id, self.vuln_name, severity=self.vuln_severity,
                                            resolution=self.resolution, vulnerable_since="", scan_id=self.vuln_scan_id)

                self.createAndAddVulnWebToService(host_id, service_to_interface,  self.vuln_name,
                                                  severity=self.vuln_severity, resolution=self.resolution,
                                                  website=self.website, path=self.pathfile)
        else:
            print('Error in xml report... Exiting...')
            return


def createPlugin():
    return CheckmarxPlugin()

# I'm Py3
