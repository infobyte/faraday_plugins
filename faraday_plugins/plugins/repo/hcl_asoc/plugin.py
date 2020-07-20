#!/usr/bin/env python
# -*- coding: utf-8 -*-
from faraday_plugins.plugins.plugin import PluginXMLFormat
from datetime import datetime
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
import re

__author__ = 'Blas Moyano'
__copyright__ = 'Copyright 2020, Faraday Project'
__credits__ = ['Blas Moyano']
__license__ = ''
__version__ = '1.0.0'
__status__ = 'Development'


class HclAsocParser:
    def __init__(self, xml_output):
        self.tree = self.parse_xml(xml_output)
        if self.tree:
            self.operating_system = self.tree.attrib['technology']
            url_group = [tags.tag for tags in self.tree]
            check_url = True if 'url-group' in url_group else False
            if check_url:
                self.urls = self.get_urls_info(self.tree.find('url-group'))
            else:
                self.urls = None
            self.layout = self.get_layout_info(self.tree.find('layout'))
            self.item = self.get_issue_type(self.tree.find('issue-type-group'))
            self.name_scan = self.get_issue_data(self.tree.find('advisory-group'))
        else:
            self.tree = None

    def parse_xml(self, xml_output):
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError as err:
            print('SyntaxError In xml: %s. %s' % (err, xml_output))
            return None
        return tree

    def get_layout_info(self, tree):
        info_layout = {
            "name": "Not info" if tree.find("application-name") is None else tree.find("application-name").text,
            "date": "Not info" if tree.find("report-date") is None else tree.find("report-date").text,
            "details": f'Departamento: {"Not info" if tree.find("department") is None else tree.find("department").text}'
                       f'Compania: {"Not info" if tree.find("company") is None else tree.find("company").text}'
                       f'Titulo Reporte: {"Not info" if tree.find("title") is None else tree.find("title").text}'
        }
        return info_layout

    def get_issue_type(self, tree):
        list_item = []
        for item in tree:
            item_info = {
                "id": item.attrib.get('id', None),
                "name": item.find("name").text,
                "severity_id": item.attrib.get('severity-id', None),
                "severity": item.attrib.get('severity', None)
            }
            list_item.append(item_info)

        return list_item

    def get_issue_data(self, tree):
        list_item_data = []
        item_data = {}
        for item in tree:
            for adivisory in item:
                item_data = {
                    "id": item.attrib.get('id', None),
                    "name": "Not info" if adivisory.find("name") is None else adivisory.find("name").text,
                    "description": "Not info" if adivisory.find("testDescription") is None else
                    adivisory.find("testDescription").text,
                    "threatClassification": {
                        "name": "Not info" if adivisory.find("threatClassification/name") is None else
                        adivisory.find("threatClassification/name").text,
                        "reference": "Not info" if adivisory.find("threatClassification/reference") is None else
                        adivisory.find("threatClassification/reference").text,
                    },
                    "testTechnicalDescription": self.get_parser(adivisory.find("testTechnicalDescription")),
                    "causes": "Not info" if adivisory.find("causes/cause") is None else
                    adivisory.find("causes/cause").text,
                    "securityRisks": "Not info" if adivisory.find("securityRisks/securityRisk") is None else
                    adivisory.find("securityRisks/securityRisk").text,
                    "affectedProducts": "Not info" if adivisory.find("affectedProducts/affectedProduct") is None else
                    adivisory.find("affectedProducts/affectedProduct").text,
                    "cwe": "Not info" if adivisory.find("cwe/link") is None else adivisory.find("cwe/link").text,
                    "xfid": "Not info" if adivisory.find("xfid/link") is None else adivisory.find("cwe/link").text,
                    "references": self.get_parser(adivisory.find("references")),
                    "fixRecommendations": self.get_parser(adivisory.find("fixRecommendations/fixRecommendation"))
                }
        return list_item_data

    def get_parser(self, tree):
        text_join = ""
        code_join = ""
        link_join = ""

        if tree.tag == 'testTechnicalDescription':
            for text_info in tree.findall('text'):
                text_join += text_info.text

            for code_info in tree.findall('code'):
                text_join += code_info.text

            tech_data = {
                "text": text_join,
                "code": code_join
            }

        elif tree.tag == 'references':
            for text_info in tree.findall('text'):
                text_join += "no info " if text_info.text is None else text_info.text

            for link_info in tree.findall('link'):
                link_join += "no info " if link_info.text is None else link_info.text
                link_join += link_info.attrib.get('target', 'not target')

            tech_data = {
                "text": text_join,
                "Link": link_join
            }

        elif tree.tag == 'fixRecommendation':
            for text_info in tree.findall('text'):
                text_join += "no info " if text_info.text is None else text_info.text

            for link_info in tree.findall('link'):
                link_join += "no info " if link_info.text is None else link_info.text
                link_join += link_info.attrib.get('target', 'not target')

            tech_data = {
                "text": text_join,
                "link": link_join
            }

        return tech_data

    def get_urls_info(self, tree):
        list_url = []
        for url in tree:
            url_info = {
                "id": "Not info" if url.find("issue-type") is None else url.find("issue-type").text,
                "url": "Not info" if url.find("name") is None else url.find("name").text,
            }
            list_url.append(url_info)

        return list_url


class HclAsocPlugin(PluginXMLFormat):
    def __init__(self):
        super().__init__()
        self.identifier_tag = "xml-report"
        self.id = 'HclAsoc'
        self.name = 'HCL ASOC XML Output Plugin'
        self.plugin_version = '1.0.0'
        self.version = '1.0.0'
        self.framework_version = '1.0.0'
        self.options = None
        self.protocol = None
        self.port = '80'
        self.address = None

    def report_belongs_to(self, **kwargs):
        if super().report_belongs_to(**kwargs):
            report_path = kwargs.get("report_path", "")
            with open(report_path) as f:
                output = f.read()
            return re.search("createdByAppScan", output) is not None
        return False


    def parseOutputString(self, output):
        parser = HclAsocParser(output)


        # host_id = self.createAndAddHost(name=sorted(list(ip))[0], hostnames=sorted(list(url)),
        #                                description=parser.name_scan)

        # vuln_run_date = datetime.strptime(vuln_run_date, '%Y-%m-%d %H:%M:%S')

        # self.createAndAddVulnToHost(host_id=host_id, name=vuln_name, desc=vuln_desc, ref=[vuln_ref],
        #                                severity=severity, resolution=vuln_resolution, run_date=vuln_run_date,
        #                                external_id=vuln_external_id, data=str_data)


def createPlugin():
    return HclAsocPlugin()
