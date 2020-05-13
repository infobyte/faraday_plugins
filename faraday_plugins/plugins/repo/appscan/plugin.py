"""
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from faraday_plugins.plugins.plugin import PluginXMLFormat
from faraday_plugins.plugins.plugins_utils import resolve_hostname
from lxml import objectify
from urllib.parse import urlparse

__author__ = "Alejando Parodi, Ezequiel Tavella"
__copyright__ = "Copyright (c) 2015, Infobyte LLC"
__credits__ = ["Alejando Parodi", "Ezequiel Tavella"]
__license__ = ""
__version__ = "1.0"
__maintainer__ = "Ezequiel Tavella"
__status__ = "Development"



class AppscanParser():

    def __init__(self, output, logger):
        self.issue_list = []
        self.logger = logger
        self.obj_xml = objectify.fromstring(output)

    def parse_issues(self):
        issue_type = self.parse_issue_type()
        for issue in self.obj_xml["issue-group"]["item"]:
            issue_data = issue_type[issue['issue-type']['ref']]
            obj_issue = {}
            obj_issue["name"] = issue_data["name"]
            obj_issue['advisory'] = issue_data["advisory"]
            if "cve" in issue_data:
                obj_issue['cve'] = issue_data["cve"].text
            obj_issue['url'] = self.get_url(issue['url']['ref'].text)
            obj_issue['cvss_score'] = issue["cvss-score"].text
            obj_issue['response'] = self.get_response(issue)
            obj_issue['request'] = issue['variant-group']['item']["test-http-traffic"].text
            obj_issue['method'] = self.get_method(issue['variant-group']['item']["test-http-traffic"].text)
            obj_issue['severity'] = issue['severity'].text
            obj_issue['issue-description'] = self.parse_advisory_group(issue_data['advisory'])
            for recommendation in self.obj_xml["fix-recommendation-group"]["item"]:
                full_data = ""
                if recommendation.attrib['id'] == issue_data["fix-recommendation"]:
                    for data in recommendation['general']['fixRecommendation']["text"]:
                        full_data += '' + data
                    obj_issue["recomendation"] = full_data
                    if hasattr(recommendation['general']['fixRecommendation'], 'link'):
                        obj_issue["ref_link"] = recommendation['general']['fixRecommendation']['link'].text
            self.issue_list.append(obj_issue)
        return self.issue_list

    def parse_hosts(self):
        hosts_list = []
        for host in self.obj_xml['scan-configuration']['scanned-hosts']['item']:
            hosts_dict = {}
            hosts_dict['ip'] = resolve_hostname(host['host'].text)
            hosts_dict['hostname'] = host['host'].text
            hosts_dict['os'] = host['operating-system'].text
            hosts_dict['port'] = host['port'].text
            if host['port'].text == '443':
                hosts_dict['scheme'] = 'https'
            else:
                hosts_dict['scheme'] = 'http'
            hosts_list.append(hosts_dict)
        return hosts_list

    def parse_issue_type(self):
        res = {}
        for issue_type in self.obj_xml["issue-type-group"]["item"]:
            res[issue_type.attrib['id']] = {
                'name': issue_type.name.text, 
                'advisory': issue_type["advisory"]["ref"].text,
                'fix-recommendation': issue_type["fix-recommendation"]["ref"].text
                }
            if "cve" in issue_type:
                res[issue_type.attrib['id']] = {'cve': issue_type["cve"].text}
        return res

    def parse_advisory_group(self, advisory):
        """
        Function that parse advisory-group in order to get the item's description
        """
        for item in self.obj_xml["advisory-group"]["item"]:
            if item.attrib['id'] == advisory:
                return item['advisory']['testTechnicalDescription']['text'].text

    def get_url(self, ref):
        for item in self.obj_xml['url-group']['item']:
            if item.attrib['id'] == ref:
                return item['name'].text

    def get_method(self, http_traffic):
        methods_list = ['GET', 'POST', 'PUT', 'DELETE', 'CONNECT', 'PATCH', 'HEAD', 'OPTIONS']
        try:
            if http_traffic:
                for item in methods_list:
                    if http_traffic.startswith(item):
                        return item
        except TypeError:
            return None
        return None

    def get_response(self, node):
        try:
            response = node['variant-group']['item']['issue-information']["testResponseChunk"].text
            return response
        except AttributeError:
            return None

    def get_scan_information(self):

        scan_information = "File: " + self.obj_xml["scan-information"]["scan-file-name"]\
            + "\nStart: " + self.obj_xml["scan-information"]["scan-date-and-time"]\
            + "\nSoftware: " + self.obj_xml["scan-information"]["product-name"]\
            + "\nVersion: " + self.obj_xml["scan-information"]["product-version"]\
            + "\nScanner Elapsed time: " + self.obj_xml["scan-summary"]["scan-Duration"]

        return scan_information


class AppscanPlugin(PluginXMLFormat):
    """ Example plugin to parse Appscan XML report"""

    def __init__(self):
        super().__init__()
        self.identifier_tag = "xml-report"
        self.id = "Appscan"
        self.name = "Appscan XML Plugin"
        self.plugin_version = "0.0.1"
        self.options = None
        self.open_options = {"mode": "r", "encoding": "utf-8"}

    def parseOutputString(self, output):
        try:
            parser = AppscanParser(output, self.logger)
            issues = parser.parse_issues()
            scanned_hosts = parser.parse_hosts()
            hosts_dict = {}
            for host in scanned_hosts:
                host_id = self.createAndAddHost(host['ip'], os=host['os'], hostnames=[host['hostname']])
                service_id = self.createAndAddServiceToHost(
                    host_id,
                    host['scheme'],
                    ports=[host['port']],
                    protocol="tcp?HTTP")
                if host['port']:
                    if host['port'] not in ('443', '80'):
                        key_url = f"{host['scheme']}://{host['hostname']}:{host['port']}"
                    else:
                        key_url = f"{host['scheme']}://{host['hostname']}"
                else:
                    key_url = f"{host['scheme']}://{host['hostname']}"
                hosts_dict[key_url] = {'host_id': host_id, 'service_id': service_id}
            for issue in issues:
                url_parsed = urlparse(issue['url'])
                url_string = f'{url_parsed.scheme}://{url_parsed.netloc}'
                for key in hosts_dict:
                    if url_string == key:
                        h_id = hosts_dict[key]['host_id']
                        s_id = hosts_dict[key]['service_id']
                        refs = []
                        if "ref_link" in issue:
                            refs.append(f"Fix link: {issue['ref_link']}" )
                        if "cvss_score" in issue:
                            refs.append(f"CVSS Score: {issue['cvss_score']}")
                        if "cve" in issue:
                            refs.append(f"CVE: {issue['cve']}")
                        if "advisory" in issue:
                            refs.append(f"Advisory: {issue['advisory']}")
                        self.createAndAddVulnWebToService(
                            h_id,
                            s_id,
                            issue["name"],
                            desc=issue["issue_description"] if "issue_description" in issue else "",
                            ref=refs,
                            severity=issue["severity"],
                            resolution=issue["recomendation"],
                            website=url_parsed.netloc,
                            path=url_parsed.path,
                            request=issue["request"] if "request" in issue else "",
                            response=issue["response"] if issue["response"] else "",
                            method=issue["method"] if issue["method"] else "")
        except Exception as e:
            self.logger.error("Parsing Output Error: %s", e)


def createPlugin():
    return AppscanPlugin()

# I'm Py3
