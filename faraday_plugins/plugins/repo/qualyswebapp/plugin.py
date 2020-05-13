#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re
from urllib.parse import urlparse

from dateutil.parser import parse

from faraday_plugins.plugins.plugin import PluginXMLFormat

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


class QualysWebappParser:
    def __init__(self, xml_output):
        self.tree = self.parse_xml(xml_output)
        if self.tree:
            self.info_results = self.get_results_vul(self.tree.find('RESULTS'))
            self.info_glossary = self.get_glossary_qid(self.tree.find('GLOSSARY'))
            self.info_appendix = self.get_appendix(self.tree.find('APPENDIX'))
        else:
            self.tree = None

    def parse_xml(self, xml_output):
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError as err:
            print('SyntaxError In xml: %s. %s' % (err, xml_output))
            return None
        return tree

    def get_appendix(self, tree):
        for self.appendix_tags in tree:
            yield Appendix(self.appendix_tags)

    def get_glossary_qid(self, tree):
        for self.glossary_tags in tree.find('QID_LIST'):
            yield Glossary(self.glossary_tags)

    def get_results_vul(self, tree):
        for self.results_tags in tree.find('VULNERABILITY_LIST'):
            yield Results(self.results_tags)

class Appendix():
    def __init__(self, appendix_tags):
        if appendix_tags.tag == 'SCAN_LIST':
            self.lista_scan = self.get_scan(appendix_tags.find('SCAN'))
        elif appendix_tags.tag == 'WEBAPP':
            self.lista_webapp = self.get_webapp(appendix_tags)

    def get_scan(self, appendix_tags):
        self.result_scan = {}
        for scan in appendix_tags:
            self.result_scan[scan.tag] = scan.text
        return self.result_scan

    def get_webapp(self, appendix_tags):
        self.result_webapp = {}
        for webapp in appendix_tags:
            self.result_webapp[webapp.tag] = webapp.text
        return self.result_webapp


class Glossary():
    def __init__(self, glossary_tags):
        self.lista_qid = self.get_qid_list(glossary_tags)


    def get_qid_list(self, qid_list_tags):
        self.dict_result_qid = {}
        for qid in qid_list_tags:
            self.dict_result_qid[qid.tag] = qid.text
        return self.dict_result_qid


class Results():
    def __init__(self, glossary_tags):
        self.lista_vul = self.get_qid_list(glossary_tags)

    def get_qid_list(self, vul_list_tags):
        self.dict_result_vul = {}
        for vul in vul_list_tags:
            self.dict_result_vul[vul.tag] = vul.text
        return self.dict_result_vul


class QualysWebappPlugin(PluginXMLFormat):
    def __init__(self):
        super().__init__()
        self.identifier_tag = ["WAS_SCAN_REPORT"]
        self.id = 'QualysWebapp'
        self.name = 'QualysWebapp XML Output Plugin'
        self.plugin_version = '1.0.0'
        self.version = '1.0.0'
        self.framework_version = '1.0.0'
        self.options = None
        self.protocol = None
        self.port = '80'
        self.address = None

    def parseOutputString(self, output):
        hostnames = []

        parser = QualysWebappParser(output)

        if not parser.info_appendix:
            return

        self.scan_list_result = []
        for host_create in parser.info_appendix:
            self.scan_list_result.append(host_create)

        self.credential = self.scan_list_result[0].lista_scan.get('AUTHENTICATION_RECORD')
        os = self.scan_list_result[1].lista_webapp.get('OPERATING_SYSTEM')

        if self.scan_list_result[1].lista_webapp.get('URL'):
            initial_url = self.scan_list_result[1].lista_webapp.get('URL')
            parsed_url = urlparse(initial_url)
            hostnames = [parsed_url.netloc]

        glossary = []
        for glossary_qid in parser.info_glossary:
            glossary.append(glossary_qid.dict_result_qid)

        for v in parser.info_results:
            url = urlparse(v.dict_result_vul.get('URL'))

            host_id = self.createAndAddHost(name=url.netloc, os=os, hostnames=hostnames)

            vuln_scan_id = v.dict_result_vul.get('QID')

            # Data in the xml is in different parts, we look into the glossary
            vuln_data = next((item for item in glossary if item["QID"] == vuln_scan_id), None)
            vuln_name = vuln_data.get('TITLE')
            vuln_desc = vuln_data.get('DESCRIPTION')

            raw_severity = int(vuln_data.get('SEVERITY', 0))
            vuln_severity = raw_severity - 1

            run_date = parse(v.dict_result_vul.get('FIRST_TIME_DETECTED'))
            vuln_resolution = vuln_data.get('SOLUTION')

            vuln_ref = []
            if vuln_data.get('CVSS_BASE'):
                vuln_ref = ["CVSS: {}".format(vuln_data.get('CVSS_BASE'))]

            vuln_data_add = "ID: {}, DETECTION_ID: {}, CATEGORY: {}, GROUP: {}, URL: {}, IMPACT: {}".format(
                v.dict_result_vul.get('ID'), v.dict_result_vul.get('DETECTION_ID'), vuln_data.get('CATEGORY'),
                vuln_data.get('GROUP'), v.dict_result_vul.get('URL'), vuln_data.get('IMPACT'))

            self.createAndAddVulnToHost(host_id=host_id, name=vuln_name, desc=vuln_desc, ref=vuln_ref,
                                        severity=vuln_severity, resolution=vuln_resolution, run_date=run_date,
                                        external_id=vuln_scan_id, data=vuln_data_add)


def createPlugin():
    return QualysWebappPlugin()
