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
