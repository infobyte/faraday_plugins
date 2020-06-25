#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from faraday_plugins.plugins.plugin import PluginXMLFormat
from datetime import datetime
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


class AppSpiderParser:
    def __init__(self, xml_output):
        self.tree = self.parse_xml(xml_output)
        if self.tree:
            self.vuln_list = self.tree.find('VulnList')
            self.name_scan = self.tree.find('ScanName').text
        else:
            self.tree = None

    def parse_xml(self, xml_output):
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError as err:
            print('SyntaxError In xml: %s. %s' % (err, xml_output))
            return None
        return tree


class AppSpiderPlugin(PluginXMLFormat):
    def __init__(self):
        super().__init__()
        self.identifier_tag = ["VulnSummary"]
        self.id = 'AppSpider'
        self.name = 'AppSpider XML Output Plugin'
        self.plugin_version = '1.0.0'
        self.version = '1.0.0'
        self.framework_version = '1.0.0'
        self.options = None
        self.protocol = None
        self.port = '80'
        self.address = None

    def parseOutputString(self, output):
        parser = AppSpiderParser(output)
        websites = []
        websites_ip = []

        for vuln in parser.vuln_list:
            websites.append(vuln.find('WebSite').text)
            websites_ip.append(vuln.find('WebSiteIP').text)

        url = set(websites)
        ip = set(websites_ip)
        if None in ip:
            ip.remove(None)

        host_id = self.createAndAddHost(name=sorted(list(ip))[0], hostnames=sorted(list(url)),
                                        description=parser.name_scan)
        data_info = []

        for vulns in parser.vuln_list:
            vuln_name = vulns.find('VulnType').text
            vuln_desc = vulns.find('Description').text
            vuln_ref = vulns.find('VulnUrl').text
            severity = vulns.find('AttackScore').text
            vuln_resolution = vulns.find('Recommendation').text
            vuln_external_id = vulns.find('DbId').text
            vuln_run_date = vulns.find('ScanDate').text
            data_info.append(vulns.find('AttackClass').text)
            data_info.append(vulns.find('CweId').text)
            data_info.append(vulns.find('CAPEC').text)
            data_info.append(vulns.find('DISSA_ASC').text)
            data_info.append(vulns.find('OWASP2007').text)
            data_info.append(vulns.find('OWASP2010').text)
            data_info.append(vulns.find('OWASP2013').text)
            data_info.append(vulns.find('OVAL').text)
            data_info.append(vulns.find('WASC').text)

            if severity == '1-Informational':
                severity = 0
            elif severity == '2-Low':
                severity = 1
            elif severity == '3-Medium':
                severity = 2
            elif severity == '4-High':
                severity = 3
            else:
                severity = 10

            str_data = f'AttackClass: {data_info[0]}, CweId: {data_info[1]}, CAPEC: {data_info[2]}, ' \
                       f'DISSA_ASC: {data_info[3]}, OWASP2007: {data_info[4]}, OWASP2010: {data_info[5]}, ' \
                       f'OWASP2013: {data_info[6]}, OVAL: {data_info[7]}, WASC: {data_info[8]}'

            if vuln_run_date is None:
                vuln_run_date = None
            else:
                vuln_run_date = datetime.strptime(vuln_run_date, '%Y-%m-%d %H:%M:%S')

            self.createAndAddVulnToHost(host_id=host_id, name=vuln_name, desc=vuln_desc, ref=[vuln_ref],
                                        severity=severity, resolution=vuln_resolution, run_date=vuln_run_date,
                                        external_id=vuln_external_id, data=str_data)


def createPlugin():
    return AppSpiderPlugin()
