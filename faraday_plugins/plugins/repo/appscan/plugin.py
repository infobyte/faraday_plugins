from urllib.parse import urlparse

from faraday_plugins.plugins.plugin import PluginXMLFormat

import xml.etree.ElementTree as ET

__author__ = "Nicolas Rebagliati"
__copyright__ = "Copyright (c) 2021, Infobyte LLC"
__credits__ = ["Nicolas Rebagliati"]
__license__ = ""
__version__ = "1.0"
__maintainer__ = "Nicolas Rebagliati"
__status__ = "Development"


class AppScanParser:

    def __init__(self, xml_output):
        tree = self.parse_xml(xml_output)
        if tree:
            self.scan_type = tree.attrib['technology']
            self.issue_types = self.get_issue_types(tree.find('issue-type-group'))
            if self.scan_type == "SAST":
                self.fixes = self.get_fixes(tree.find("fix-group-group"))
                self.issues = self.get_sast_issues(tree.find("issue-group"))
            elif self.scan_type == "DAST":
                self.hosts = self.get_hosts(tree.find('scan-configuration/scanned-hosts'))
                self.remediations = self.get_remediations(tree.find('remediation-group'))
                self.entities = self.get_entity_groups(tree.find('entity-group'))
                self.issues = self.get_dast_issues(tree.find("issue-group"))

    @staticmethod
    def parse_xml(xml_output):
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError as err:
            print(f'SyntaxError In xml: {err}. {xml_output}')
            return None
        return tree

    @staticmethod
    def get_fixes(tree):
        fixes = {}
        for item in tree:
            fix_id = item.attrib['id']
            library = item.find("LibraryName").text
            location = item.find("Location").text
            fixes[fix_id] = {"library": library, "location": location}
        return fixes

    @staticmethod
    def get_issue_types(tree):
        issue_types = {}
        for item in tree:
            type_id = item.attrib['id']
            name = item.find("name").text
            issue_types[type_id] = name
            cve = item.find("cve")
            if cve and cve.text:
                issue_types[f"{type_id}_cve"] = cve.text
        return issue_types

    @staticmethod
    def get_remediations(tree):
        remediations = {}
        for item in tree:
            remediation_id = item.attrib['id']
            name = item.find("name").text
            remediations[remediation_id] = name
        return remediations

    @staticmethod
    def get_hosts(tree):
        hosts = {}
        for item in tree:
            host = item.find("host").text
            port = item.find("port").text
            operating_system = item.find("operating-system").text
            if "unknown" in operating_system.lower():
                operating_system = "unknown"
            web_server = item.find("web-server").text
            application_server = item.find("application-server").text
            service_name = f"{web_server} ({application_server})"
            host_key = f"{host}-{port}"
            hosts[host_key] = {"host": host, "port": port, "os": operating_system,
                               "service_name": service_name}
        return hosts

    @staticmethod
    def get_entity_groups(tree):
        entity_groups = {}
        for item in tree:
            entity_id = item.attrib['id']
            name = item.find("name").text
            url = item.find("url-name").text
            type = item.find("entity-type").text
            url_data = urlparse(url)
            website = f"{url_data.scheme}://{url_data.netloc}"
            host = url_data.netloc.split(":")[0]
            if url_data.port:
                port = url_data.port
            else:
                if url_data.scheme == "http":
                    port = 80
                elif url_data.scheme == "https":
                    port = 443
            path = url_data.path
            entity_groups[entity_id] = {"name": name, "host": host, "port": port, "url": url,
                                        "type": type, "website": website, "path": path}
        return entity_groups

    def get_dast_issues(self, tree):
        dast_issues = []
        for item in tree:
            entity = self.entities[item.find("entity/ref").text]
            host = entity["host"].replace('\\','/')
            port = entity["port"]
            name = self.issue_types[item.find("issue-type/ref").text]
            severity = 0 if item.find("severity-id") is None else int(item.find("severity-id").text)
            resolution = self.remediations[item.find("remediation/ref").text]
            description = "" if item.find("variant-group/item/reasoning") is None \
                else item.find("variant-group/item/reasoning").text
            request = "" if item.find("variant-group/item/test-http-traffic") is None \
                else item.find("variant-group/item/test-http-traffic").text
            response = "" if item.find("variant-group/item/issue-information/testResponseChunk") is None \
                else item.find("variant-group/item/issue-information/testResponseChunk").text
            cvss = None if item.find("cvss-score") is None else f"CVSS: {item.find('cvss-score').text}"
            cvss_base_vector = None if item.find('cvss-vector/base-vector') is None \
                else f"CVSS-base-vector: {item.find('cvss-vector/base-vector').text}"
            cvss_temporal_vector = None if item.find('cvss-vector/temporal-vector') is None \
                else f"CVSS-temporal-vector: {item.find('cvss-vector/temporal-vector').text}"
            cvss_environmental_vector = None if item.find('cvss-vector/environmental-vector') is None \
                else f"CVSS-environmental-vector: {item.find('cvss-vector/environmental-vector').text}"
            cwe = None if item.find("cwe") is None else item.find('cwe').text
            if item.attrib.get("cve"):
                cve = None if item.find("variant-group/item/issue-information/display-name") is None \
                    else item.find('variant-group/item/issue-information/display-name').text
                if "CVE" not in cve:
                    cve = f"CVE-{cve}"
                cve_url = item.attrib["cve"]
            else:
                cve = None
                cve_url = None
            if cve is None:
                cve = self.issue_types.get(f"{item.find('issue-type/ref').text}_cve", None)
            host_key = f"{host}-{port}"
            issue_data = {
                "host": host,
                "port": port,
                "os": self.hosts[host_key]["os"],
                "service_name": self.hosts[host_key]["service_name"],
                "name": name,
                "severity": severity,
                "desc": description,
                "ref": [],
                "resolution": resolution,
                "request": request,
                "response": response,
                "website": entity['website'],
                "path": entity['path'],
                "cve": []
            }
            if cve:
                issue_data["cve"].append(cve)
            if cve_url:
                issue_data["ref"].append(cve_url)
            if cwe:
                issue_data["ref"].append(f"CWE: {cwe}")
            if cvss:
                issue_data["ref"].append(cvss)
            if cvss_base_vector:
                issue_data["ref"].append(cvss_base_vector)
            if cvss_temporal_vector:
                issue_data["ref"].append(cvss_temporal_vector)
            if cvss_environmental_vector:
                issue_data["ref"].append(cvss_environmental_vector)
            dast_issues.append(issue_data)
        return dast_issues

    def get_sast_issues(self, tree):
        sast_issues = []
        for item in tree:
            name = self.issue_types[item.find("issue-type/ref").text]
            source_file = item.attrib["filename"].replace('\\', '/')
            severity = 0 if item.find("severity-id") is None else int(item.find("severity-id").text)
            description = item.find("fix/item/general/text").text
            resolution = "" if item.find("variant-group/item/issue-information/fix-resolution-text") is None \
                else item.find("variant-group/item/issue-information/fix-resolution-text").text
            fix_id = item.attrib.get("fix-group-id")
            if fix_id:
                fix = self.fixes[fix_id]
                resolution = f"{resolution}\nLibrary: {fix['library']}\nLocation: {fix['location']}"
            cvss = None if item.find("cvss-score") is None else f"CVSS: {item.find('cvss-score').text}"
            cvss_base_vector = None if item.find('cvss-vector/base-vector') is None \
                else f"CVSS-base-vector: {item.find('cvss-vector/base-vector').text}"
            cvss_temporal_vector = None if item.find('cvss-vector/temporal-vector') is None \
                else f"CVSS-temporal-vector: {item.find('cvss-vector/temporal-vector').text}"
            cvss_environmental_vector = None if item.find('cvss-vector/environmental-vector') is None \
                else f"CVSS-environmental-vector: {item.find('cvss-vector/environmental-vector').text}"
            cwe = None if item.find("cwe/ref") is None else item.find('cwe/ref').text
            if item.attrib.get("cve"):
                cve = None if item.find("variant-group/item/issue-information/display-name") is None \
                    else item.find('variant-group/item/issue-information/display-name').text
                if "CVE" not in cve:
                    cve = f"CVE-{cve}"
                cve_url = item.attrib["cve"]
            else:
                cve = None
                cve_url = None
            issue_data = {
                "source_file": source_file,
                "name": name,
                "severity": severity,
                "desc": description,
                "ref": [],
                "resolution": resolution,
                "cve": []
            }

            if cve:
                issue_data["cve"].append(cve)
            if cve_url:
                issue_data["ref"].append(cve_url)
            if cwe:
                issue_data["ref"].append(f"CWE: {cwe}")
            if cvss:
                issue_data["ref"].append(cvss)
            if cvss_base_vector:
                issue_data["ref"].append(cvss_base_vector)
            if cvss_temporal_vector:
                issue_data["ref"].append(cvss_temporal_vector)
            if cvss_environmental_vector:
                issue_data["ref"].append(cvss_environmental_vector)
            # Build data
            data = []
            if item.attrib.get("caller"):
                data.append(f"Caller: {item.attrib.get('caller')}")
            if item.find("variant-group/item/issue-information/method-signature") is not None:
                data.append(f"Method: {item.find('variant-group/item/issue-information/method-signature').text}")
            if item.find("variant-group/item/issue-information/method-signature2") is not None:
                data.append(f"Location: {item.find('variant-group/item/issue-information/method-signature2').text}")
            line = item.find("location")
            highlight = item.find("variant-group/item/issue-information/call-trace/call-invocation/context/highlight")
            if highlight is not None:
                data.append(f" {highlight.text}")
                issue_data["desc"] += "\n" + highlight.text
            if line is not None and len(line.text.split(':')) > 1 and line.text.split(':')[-1].isdigit():
                data.append(f"line {line.text.split(':')[-1]}")
                issue_data["desc"] += f"line {line.text.split(':')[-1]}"
            issue_data['data'] = "\n".join(data)
            sast_issues.append(issue_data)
        return sast_issues


class AppScanPlugin(PluginXMLFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "xml-report"
        self.id = 'Appscan'
        self.name = 'Appscan XML Plugin'
        self.plugin_version = '0.0.1'
        self.version = '1.0.0'
        self.framework_version = '1.0.0'

    def parseOutputString(self, output):
        parser = AppScanParser(output)
        scan_type = parser.scan_type

        if scan_type == 'DAST':
            for issue in parser.issues:
                host = issue.pop("host")
                port = issue.pop("port")
                service_name = issue.pop("service_name")
                ip = self.resolve_hostname(host)
                host_os = issue.pop("os")
                host_id = self.createAndAddHost(ip, hostnames=host, os=host_os)
                service_id = self.createAndAddServiceToHost(host_id, service_name, ports=port)
                self.createAndAddVulnWebToService(host_id=host_id, service_id=service_id, **issue)

        elif scan_type == 'SAST':
            for issue in parser.issues:
                source_file = issue.pop('source_file')
                host_id = self.createAndAddHost(source_file)
                self.createAndAddVulnToHost(host_id=host_id, **issue)


def createPlugin(ignore_info=False, hostname_resolution=True):
    return AppScanPlugin(ignore_info=ignore_info, hostname_resolution=hostname_resolution)
