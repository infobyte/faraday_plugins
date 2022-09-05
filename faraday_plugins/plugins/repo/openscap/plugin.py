#!/usr/bin/env python
"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import ipaddress
from datetime import datetime

from lxml import etree

from faraday_plugins.plugins.plugin import PluginXMLFormat

__author__ = 'Blas Moyano'
__copyright__ = 'Copyright 2020, Faraday Project'
__credits__ = ['Blas Moyano']
__license__ = ''
__version__ = '1.0.0'
__status__ = 'Development'


class OpenScapParser:
    def __init__(self, xml_output):
        self.tree = self.parse_xml(xml_output)

        if self.tree is not None:
            self.rule_date = self.get_parser_rule(self.tree.findall('Rule', self.tree.nsmap))
            self.result_data = self.get_parser_result(self.tree.findall('TestResult', self.tree.nsmap))
            self.tree = None

    def parse_xml(self, xml_output):
        try:
            parser = etree.XMLParser(recover=True)
            tree = etree.fromstring(xml_output, parser=parser)
        except SyntaxError as err:
            print(f'SyntaxError In xml: {err}. {xml_output}')
            return None
        return tree

    def get_parser_rule(self, tree):
        list_rules = []
        for rule in tree:
            title = rule.find('title', self.tree.nsmap)
            ident = rule.find('ident', self.tree.nsmap)
            check = rule.find('check', self.tree.nsmap)
            check_ref = rule.find('check/check-content-ref', self.tree.nsmap)
            try:
                ident_result = ident.text
            except AttributeError:
                ident_result = ""
            json_rule = {
                "rule_id": rule.attrib.get('id', None),
                "rule_sev": rule.attrib.get('severity', None),
                "rule_title": title.text,
                "rule_ident": ident_result,
                "rule_check": check.attrib.get('system', None),
                "rule_ref_name": check_ref.attrib.get('name', None),
                "rule_ref_href": check_ref.attrib.get('href', None)
            }
            list_rules.append(json_rule)
        return list_rules

    def get_parser_result(self, tree):
        list_result = []
        list_ip = []
        list_mac = []
        list_data = []
        for result in tree:
            title = result.find('title', self.tree.nsmap)
            target = result.find('target', self.tree.nsmap)
            ips = result.findall('target-address', self.tree.nsmap)
            target_facts = result.findall('target-facts/fact', self.tree.nsmap)
            rule_result = result.findall('rule-result', self.tree.nsmap)

            for ip in ips:
                list_ip.append(ip.text)

            for mac in target_facts:
                fact_name = mac.attrib.get('name', None)
                if fact_name == 'urn:xccdf:fact:ethernet:MAC':
                    list_mac.append(mac.text)

            for data in rule_result:
                list_ident = []
                idents = data.findall('ident', self.tree.nsmap)
                check = data.find('check', self.tree.nsmap)
                check_ref = data.find('check/check-content-ref', self.tree.nsmap)

                for ident in idents:
                    json_ident = {
                        "system": data.attrib.get('system', None),
                        "text": ident.text
                    }
                    list_ident.append(json_ident)

                json_data = {
                    "id": data.attrib.get('idref', None),
                    "time": data.attrib.get('time', None),
                    "severity": data.attrib.get('severity', None),
                    "ident": list_ident,
                    "check": check.attrib.get('system', None),
                    "ref_name": check_ref.attrib.get('name', None),
                    "ref_href": check_ref.attrib.get('href', None)
                }

                status = data.find('result', self.tree.nsmap)
                if status.text == 'fail':
                    list_data.append(json_data)

            json_result = {
                "id": result.attrib.get('id', None),
                "start_time": result.attrib.get('start-time', None),
                "end_time": result.attrib.get('end-time', None),
                "result_title": title.text,
                "target": target.text,
                "ips": list_ip,
                "mac": list_mac,
                "rule_result": list_data
            }
            list_result.append(json_result)
        return list_result


class OpenScapPlugin(PluginXMLFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "Benchmark"
        self.id = 'OpenScap'
        self.name = 'OpenScap XML Output Plugin'
        self.plugin_version = '1.0.0'
        self.version = '1.0.0'
        self.framework_version = '1.0.0'
        self.options = None
        self.protocol = None
        self.port = '80'

    def parseOutputString(self, output):
        parser = OpenScapParser(output)
        ips = []

        for ip in parser.result_data[0]['ips']:
            len_start_port = ip.find(":")
            if len_start_port > -1:
                ip = ip[:len_start_port]
            try:
                ipaddress.ip_address(ip)
                ips.append(ip)
            except ValueError:
                pass
        for ip in ips:
            if ip != '127.0.0.1':
                ip = ip
                ips.remove(ip)
                break

        list_mac = parser.result_data[0]['mac']
        for mac in list_mac:
            if mac != '00:00:00:00:00:00':
                mac_address = mac
                list_mac.remove(mac_address)
                break

        description = f'Title: {parser.result_data[0]["result_title"]} ' \
                      f'Ips: {ips} ' \
                      f'Macs: {list_mac}'
        host_id = self.createAndAddHost(
            name=ip,
            hostnames=[parser.result_data[0]['target']],
            description=description,
            mac=mac_address
        )

        rules_fail = parser.result_data[0]['rule_result']
        if rules_fail:
            info_rules = parser.rule_date
            severity = 0

            for rule in rules_fail:
                vuln_run_date = datetime.strptime(
                    rule['time'].replace('T', ' '),
                    '%Y-%m-%d %H:%M:%S')

                if rule['severity'] == 'low':
                    severity = 1
                elif rule['severity'] == 'medium':
                    severity = 2
                elif rule['severity'] == 'high':
                    severity = 3

                desc = f'name: {rule["ref_name"]} - link: {rule["ref_href"]}'

                for info in info_rules:
                    if rule['id'] == info['rule_id']:
                        vuln_name = info['rule_title']
                        vuln_data = info['rule_check']
                        vuln_cve = info['rule_ident']

                self.createAndAddVulnToHost(
                    host_id,
                    vuln_name,
                    desc=desc,
                    severity=severity,
                    data=vuln_data,
                    external_id=rule['id'],
                    run_date=vuln_run_date,
                    cve=[vuln_cve])


def createPlugin(*args, **kwargs):
    return OpenScapPlugin(*args, **kwargs)
