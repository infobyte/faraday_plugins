from faraday_plugins.plugins.plugin import PluginXMLFormat

import xml.etree.ElementTree as ET

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2021, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0"
__maintainer__ = "Gonzalo Martinez"
__status__ = "Development"


class SyhuntParser:

    def __init__(self, xml_output):
        tree = self.parse_xml(xml_output)
        if tree:
            self.scan_type = "SAST" if "Application Code Scan" in tree.find("scan_method").text else "DAST"
            self.issues = self.get_issues(tree.find("hosts"))

    @staticmethod
    def parse_xml(xml_output):
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError as err:
            print(f'SyntaxError In xml: {err}. {xml_output}')
            return None
        return tree

    def get_issues(self, tree):
        issues = []
        if self.scan_type == "DAST":
            for host in tree:
                h = self.get_host(host)
                vulns = [self.get_vulns(vuln) for vuln in host.find("vulnerabilities")]
                issues.append({
                    "host": h,
                    "vulns": vulns
                })
        else:
            for host in tree:
                for vuln in host.find("vulnerabilities"):
                    issues.append(self.get_vulns(vuln))
        return issues

    def get_vulns(self, vuln):
        name = vuln.find("check_name").text
        desc = vuln.find("description").text
        resolution = vuln.find("solution").text
        cvss2 = self.get_cvss(vuln.find("cvss/cvss2"))
        cvss3 = self.get_cvss(vuln.find("cvss/cvss3"), prefix="CVSS:3.0/")
        severity = vuln.find("cvss/cvss3/severity").text
        ref = []
        if vuln.find("references/cwe"):
            ref.append("CWE:" + vuln.find("references/cwe").text)
        v = {
            "name": name,
            "desc": desc,
            "resolution": resolution,
            "ref": ref,
            "severity": severity,
            "cvss3": cvss3,
            "cvss2": cvss2
        }
        if self.scan_type == "DAST":
            v['data'] = vuln.find("request").text + "\n"
            v['data'] += f"Location {vuln.find('location').text}"
        else:
            v['location'] = vuln.find('location_appsource').text
            v['data'] = vuln.find('vulnerable_code').text
        return v

    @staticmethod
    def get_cvss(tree, prefix=""):
        cvss_vector = tree.find("vector").text
        return {'vector_string': prefix + cvss_vector}

    def get_host(self, tree):
        host = {
            "ip": tree.find("host_details/ip_address").text,
            "hostname": tree.find("host_details/host_name").text,
            "port": tree.find("scan_progress/port/port_number").text,
            "service_name": "https" if "https" in tree.find("host_details/host_name").text else "http"
        }
        return host


class SyhuntPlugin(PluginXMLFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "report"
        self.id = 'Syhunt'
        self.name = 'Syhunt XML Plugin'
        self.plugin_version = '0.0.1'
        self.version = '1.0.0'
        self.framework_version = '1.0.0'

    #uggly fix because wakiti and syhunt share identifier_tag
    def report_belongs_to(self, main_tag="", main_tag_attributes={}, **kwargs):
        match = super().report_belongs_to(main_tag, main_tag_attributes,**kwargs)
        if match:
            match = main_tag_attributes == {}
        return match

    def parseOutputString(self, output):
        parser = SyhuntParser(output)
        scan_type = parser.scan_type

        if scan_type == 'DAST':
            for issue in parser.issues:
                ip = issue["host"].pop("ip")
                port = issue["host"].pop("port")
                hostname = issue["host"].pop("hostname")
                service_name = issue["host"].pop("service_name")
                host_id = self.createAndAddHost(ip, hostnames=hostname)
                service_id = self.createAndAddServiceToHost(host_id, service_name, ports=port)
                for vuln in issue['vulns']:
                    self.createAndAddVulnWebToService(host_id=host_id, service_id=service_id, **vuln)

        elif scan_type == 'SAST':
            for issue in parser.issues:
                source_file = issue.pop('location')
                host_id = self.createAndAddHost(source_file)
                self.createAndAddVulnToHost(host_id=host_id, **issue)


def createPlugin(*args, **kwargs):
    return SyhuntPlugin(*args, **kwargs)
