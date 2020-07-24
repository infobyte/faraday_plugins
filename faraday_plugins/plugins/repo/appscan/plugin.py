#!/usr/bin/env python
# -*- coding: utf-8 -*-
from faraday_plugins.plugins.plugin import PluginXMLFormat
from faraday_plugins.plugins.plugins_utils import resolve_hostname
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
            self.host_data = None if self.tree.find('scan-configuration/scanned-hosts/item') is None else \
                self.get_scan_conf_data(self.tree.find('scan-configuration/scanned-hosts/item'))
            #self.fix_recomendation = self.get_fix_info(self.tree.find('fix-recommendation-group'))
            self.req_res = self.get_req_res(self.tree.find("issue-group"))

        else:
            self.tree = None

    def parse_xml(self, xml_output):
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError as err:
            print('SyntaxError In xml: %s. %s' % (err, xml_output))
            return None
        return tree

    def get_req_res(sef,tree):
        data_res_req = []
        for item in tree:
            if item.find("variant-group/item/issue-information"):
                resp = item.find("variant-group/item/issue-information").text
            else:
                resp = "Not Response"

            json_res_req = {
                "request": "Not request" if item.find("variant-group/item/test-http-traffic") is None else
                item.find("variant-group/item/test-http-traffic").text,
                "response": resp
            }
            data_res_req.append(json_res_req)
        return data_res_req

    # def get_fix_info(self, tree):
    #     list_fix = []
    #     for item in tree:
    #         text_info_join = []
    #         if tree.find("general"):
    #         # ACA VALIDA APP SCAN
    #             pass
    #         else:
    #             for text_tag in item.find('fixRecommendations/fixRecommendation'):
    #                 text_info_join.append(text_tag.text)
    #             info_fix = {
    #                 "id": item.attrib.get('id', None),
    #                 "name": item.attrib.get('name', None),
    #                 "text": text_info_join
    #             }
    #             list_fix.append(info_fix)
    #     return list_fix

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
            severity = item.attrib.get('severity-id', None)
            if severity is None:
                severity = item.attrib.get('maxIssueSeverity', None)

            item_info = {
                "id": item.attrib.get('id', None),
                "name": item.find("name").text,
                "severity_id": severity,
                "severity": item.attrib.get('severity', None),
                "cwe": "Not info" if item.find("cme") is None else item.find("cwe").text,
                "xfid": "Not info" if item.find("xfid") is None else item.find("xfid").text,
                "advisory": "Not info" if item.find("advisory/ref") is None else item.find("advisory/ref").text,
            }
            list_item.append(item_info)

        return list_item

    def get_issue_data(self, tree):
        list_item_data = []
        item_data = {}
        for item in tree:
            for adivisory in item:
                if adivisory.find("cwe/link"):
                    cwe = adivisory.find("cwe/link").text
                else:
                    cwe = "Not Response"

                if adivisory.find("xfid/link"):
                    xfid = adivisory.find("xfid/link").text
                else:
                    xfid = "Not Response"


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
                    "testTechnicalDescription": "Not info" if adivisory.find("testTechnicalDescription") is None else
                    self.get_parser(adivisory.find("testTechnicalDescription")),
                    "causes": "Not info" if adivisory.find("causes/cause") is None else
                    adivisory.find("causes/cause").text,
                    "securityRisks": "Not info" if adivisory.find("securityRisks/securityRisk") is None else
                    adivisory.find("securityRisks/securityRisk").text,
                    "affectedProducts": "Not info" if adivisory.find("affectedProducts/affectedProduct") is None else
                    adivisory.find("affectedProducts/affectedProduct").text,
                    "cwe": cwe,
                    "xfid": xfid,
                    "references": "Not info" if adivisory.find("references") is None else
                    self.get_parser(adivisory.find("references")),
                    "fixRecommendations": "Not info" if adivisory.find("fixRecommendations/fixRecommendation") is None else
                    self.get_parser(adivisory.find("fixRecommendations/fixRecommendation"))
                }
                list_item_data.append(item_data)
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

    def get_scan_conf_data(self, host_info):
        info_host = {
            "host": "Not info" if host_info.find("host") is None else host_info.find("host").text,
            "port": "Not info" if host_info.find("port") is None else host_info.find("port").text,
            "os": "Not info" if host_info.find("operating-system") is None else host_info.find("operating-system").text,
            "webserver": "Not info" if host_info.find("web-server") is None else host_info.find("web-server").text,
            "appserver": "Not info" if host_info.find("application-server") is None else host_info.find("application-server").text,
        }
        return info_host


class HclAsocPlugin(PluginXMLFormat):
    def __init__(self):
        super().__init__()
        self.identifier_tag = "xml-report"
        self.id = 'appscan'
        self.name = 'HCL ASOC XML Output Plugin'
        self.plugin_version = '1.0.0'
        self.version = '1.0.0'
        self.framework_version = '1.0.0'
        self.options = None
        self.protocol = None
        self.port = '80'
        self.address = None

    # def report_belongs_to(self, **kwargs):
    #     if super().report_belongs_to(**kwargs):
    #         report_path = kwargs.get("report_path", "")
    #         with open(report_path) as f:
    #             output = f.read()
    #         return re.search("createdByAppScan", output) is not None
    #     return False

    def parseOutputString(self, output):
        parser = HclAsocParser(output)
        layout = parser.layout
        operating_system = parser.operating_system
        host_data = parser.host_data
        # Listas
        urls = parser.urls
        item = parser.item
        name_scan = parser.name_scan
        #fixs = parser.fix_recomendation
        res_req = parser.req_res

        if operating_system == 'DAST':
            host_id = self.createAndAddHost(resolve_hostname(host_data['host']), os=host_data['os'],
                                            hostnames=[host_data['host']], description=layout['details'])

            service_id = self.createAndAddServiceToHost(host_id, host_data['host'], ports=host_data['port'],
                                                        protocol="tcp?HTTP", description=f'{host_data["webserver"]} - {host_data["appserver"]}')

            for vulnserv in name_scan:
                for sev in item:
                    if sev['id'] == vulnserv['id']:
                        info_severity = sev['severity_id']
                        ref = f'cwe: {sev["cwe"]} xfid: {sev["xfid"]} advisory: {sev["advisory"]}'

                for url in urls:
                    if url['id'] == vulnserv['id']:
                        url_name = url['url']

                for info_rs_rq in res_req:
                    print(info_rs_rq)
                    request = info_rs_rq['request']
                    response = info_rs_rq['response']

                self.createAndAddVulnWebToService(host_id=host_id, service_id=service_id, name=vulnserv['name'],
                                                  desc=vulnserv['description'], severity=info_severity,
                                                  path=url_name, website=host_data['host'], ref=ref,
                                                  resolution=vulnserv['fixRecommendations'], request=request,
                                                  response=response, method=request,
                                                  data=f'xfix: {vulnserv["xfid"]} cme: {vulnserv["cwe"]}')


        else:
            host_id = self.createAndAddHost('0.0.0.0', os=operating_system)
            for vulnserv in name_scan:
                for sev in item:
                    if sev['id'] == vulnserv['id']:
                        info_severity = sev['severity_id']

                self.createAndAddVulnToHost(host_id=host_id,name=vulnserv['name'], desc=vulnserv['description'],
                                            severity=info_severity, resolution=vulnserv['fixRecommendations'],
                                            data=f'xfix: {vulnserv["xfid"]} cme: {vulnserv["cwe"]}', run_date=None)

def createPlugin():
    return HclAsocPlugin()
