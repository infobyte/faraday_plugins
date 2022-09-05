"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from faraday_plugins.plugins.plugin import PluginXMLFormat

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
            print(f'SyntaxError In xml: {err}. {xml_output}')
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
                        'Number', info_pn.find('Line').find('Number').text, 'Code',
                        info_pn.find('Line').find('Code').text)
                else:
                    valor = (info_pn.tag, info_pn.text)
                lista_v.append(valor)
            lista.append(lista_v)
        return lista


class CheckmarxPlugin(PluginXMLFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = ["CxXMLResults"]
        self.id = 'Checkmarx'
        self.name = 'Checkmarx XML Output Plugin'
        self.plugin_version = '1.0.0'
        self.version = '1.0.0'
        self.framework_version = '1.0.0'
        self.options = None

    def parseOutputString(self, output):
        parser = CheckmarxXmlParser(output)
        if not parser.query:
            self.logger.warning('Error in xml report... Exiting...')
            return

        url = urlparse(parser.cx_xml_results_attribs['DeepLink'])
        port = url.port
        if not port:
            if url.scheme == 'https':
                port = 443
            elif url.scheme == 'http':
                port = 80
            else:
                port = 0
        project_name = 'ProjectName' in parser.cx_xml_results_attribs
        host_id = self.createAndAddHost(url.hostname, hostnames=[url.hostname, url.netloc])
        service_to_interface = self.createAndAddServiceToHost(host_id, name=url.scheme, ports=port)
        for vulns in parser.query:
            refs = []
            categories = 'categories' in vulns.query_attrib
            vuln_desc = ''
            if categories:
                vuln_desc = vulns.query_attrib['categories']
            vuln_name = vulns.query_attrib['name']
            vuln_severity = vulns.query_attrib['Severity']
            vuln_external_id = vulns.query_attrib['id']
            cwe = [f'CWE-{vulns.query_attrib["cweId"]}']
            data = ''
            for files_data in vulns.path_node:
                for file_data in files_data:
                    data += 60 * '-' + '\n'
                    for row_data in file_data:
                        data += ' '.join([data for data in row_data if data]) + '\n'

            for v_result in vulns.result:
                refs.append(v_result['DeepLink'])
                refs.append(v_result['FileName'])

            self.createAndAddVulnToHost(host_id, vuln_name, severity=vuln_severity,
                                        resolution=data, external_id=vuln_external_id, cwe=cwe)

            self.createAndAddVulnWebToService(host_id, service_to_interface, vuln_name,
                                              desc=vuln_desc, severity=vuln_severity,
                                              resolution=data, ref=refs, cwe=cwe)


def createPlugin(*args, **kwargs):
    return CheckmarxPlugin(*args, **kwargs)
