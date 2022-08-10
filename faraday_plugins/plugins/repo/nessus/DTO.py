from typing import List


class Attachment:
    def __init__(self, node):
        self.node = node

    @property
    def name_attr(self):
        return self.node.get("name")

    @property
    def type_attr(self):
        return self.node.get("type")

    @property
    def text(self):
        return self.node.text


class ReportItem:
    def __init__(self, node):
        self.node = node

    @property
    def port_attr(self):
        return self.node.get("port")

    @property
    def svc_name_attr(self):
        return self.node.get("svc_name")

    @property
    def protocol_attr(self):
        return self.node.get("protocol")

    @property
    def severity_attr(self):
        return self.node.get("severity")

    @property
    def plugin_id_attr(self):
        plugin_id = self.node.get("pluginID")
        if plugin_id:
            plugin_id = f'NESSUS-{plugin_id}'
        return plugin_id

    @property
    def plugin_name_attr(self):
        return self.node.get("pluginName")

    @property
    def plugin_family_attr(self):
        return self.node.get("pluginFamily")

    @property
    def agent(self):
        return self.node.findtext("agent")

    @property
    def description(self):
        return self.node.findtext("description", "Not Description")

    @property
    def fname(self):
        return self.node.findtext("fname")

    @property
    def plugin_modification_date(self):
        return self.node.findtext("plugin_modification_date")

    @property
    def plugin_name(self):

        plugin_name = self.node.findtext("plugin_name")
        if not plugin_name:
            plugin_name = self.plugin_name_attr
        return plugin_name

    @property
    def plugin_publication_date(self):
        return self.node.findtext("plugin_publication_date")

    @property
    def plugin_type(self):
        return self.node.findtext("plugin_type")

    @property
    def risk_factor(self):
        risk_factor = self.node.findtext("risk_factor")
        if risk_factor == 'None' or risk_factor is None:
            risk_factor = self.severity_attr  # I checked several external id and most of them were info
        return risk_factor

    @property
    def script_version(self):
        return self.node.findtext("script_version")

    @property
    def see_also(self):
        return self.node.findtext("see_also")

    @property
    def solution(self):
        return self.node.findtext("solution", '')

    @property
    def synopsis(self):
        return self.node.findtext("synopsis")

    @property
    def plugin_output(self):
        return self.node.findtext("plugin_output", "")

    @property
    def always_run(self):
        return self.node.findtext("always_run")

    @property
    def asset_inventory(self):
        return self.node.findtext("asset_inventory")

    @property
    def canvas_package(self):
        return self.node.findtext("canvas_package")

    @property
    def cvss3_base_score(self):
        return self.node.findtext("cvss3_base_score")

    @property
    def cvss3_temporal_score(self):
        return self.node.findtext("cvss3_temporal_score")

    @property
    def cpe(self):
        return self.node.findtext("cpe")

    @property
    def cvss3_temporal_vector(self):
        return self.node.findtext("cvss3_temporal_vector")

    @property
    def cvss3_vector(self):
        return self.node.findtext("cvss3_vector")

    @property
    def cvss2_base_score(self):
        return self.node.findtext("cvss_base_score")

    @property
    def cvss_score_rationale(self):
        return self.node.findtext("cvss_score_rationale")

    @property
    def cvss_score_source(self):
        return self.node.findtext("cvss_score_source")

    @property
    def cvss_temporal_score(self):
        return self.node.findtext("cvss_temporal_score")

    @property
    def cvss_temporal_vector(self):
        return self.node.findtext("cvss_temporal_vector")

    @property
    def cvss_vector(self):
        cvss_vector = self.node.findtext("cvss_vector")
        if cvss_vector:
            cvss_vector = cvss_vector.replace("CVSS2#", "")
        return cvss_vector

    @property
    def exploit_available(self):
        exploit_avalible = self.node.findtext("exploit_available", "")
        if exploit_avalible:
            exploit_avalible = f"Exploit available: {exploit_avalible.capitalize()}\n"
        return exploit_avalible

    @property
    def exploit_framework_canvas(self):
        return self.node.findtext("exploit_framework_canvas")

    @property
    def exploit_framework_core(self):
        return self.node.findtext("exploit_framework_core")

    @property
    def exploit_framework_d2_elliot(self):
        return self.node.findtext("exploit_framework_d2_elliot")

    @property
    def exploit_framework_metasploit(self):
        return self.node.findtext("exploit_framework_metasploit")

    @property
    def exploitability_ease(self):
        return self.node.findtext("exploitability_ease")

    @property
    def exploited_by_malware(self):
        return self.node.findtext("exploited_by_malware")

    @property
    def exploited_by_nessus(self):
        return self.node.findtext("exploited_by_nessus")

    @property
    def hardware_inventory(self):
        return self.node.findtext("hardware_inventory")

    @property
    def iava(self):
        return self.node.findtext("iava")

    @property
    def iavb(self):
        return self.node.findtext("iavb")

    @property
    def iavt(self):
        return self.node.findtext("iavt")

    @property
    def in_the_news(self):
        return self.node.findtext("in_the_news")

    @property
    def metasploit_name(self):
        return self.node.findtext("metasploit_name")

    @property
    def os_identification(self):
        return self.node.findtext("os_identification")

    @property
    def owasp(self):
        return self.node.findtext("owasp")

    @property
    def patch_publication_date(self):
        return self.node.findtext("patch_publication_date")


    @property
    def stig_severity(self):
        return self.node.findtext("stig_severity")

    @property
    def d2_elliot_name(self):
        return self.node.findtext("d2_elliot_name")

    @property
    def unsupported_by_vendor(self):
        return self.node.findtext("unsupported_by_vendor")

    @property
    def vuln_publication_date(self):
        return self.node.findtext("vuln_publication_date")

    @property
    def msft(self):
        return self.node.findtext("msft")


    @property
    def cert(self) -> list:
        return self.node.findall("cert")

    @property
    def bid(self) -> list:
        return self.node.findall("bid")

    @property
    def cve(self) -> list:
        return [i.text for i in self.node.findall("cve")]

    @property
    def cwe(self) -> list:
        return ["CWE-"+i.text for i in self.node.findall("cwe")]

    @property
    def edb_id(self) -> list:
        return self.node.findall("edb-id")

    @property
    def mskb(self) -> list:
        return self.node.findall("mskb")

    @property
    def xref(self) -> str:
        return self.node.findtext("xref")

    @property
    def attachment(self) -> Attachment:
        attachment = self.node.find("attachment")
        return Attachment(attachment) if attachment else None

    def get_data(self):
        item_tags = {}
        for i in self.node:
            item_tags.setdefault(i.tag, i.text)
        return item_tags


class Tag:
    def __init__(self, node):
        self.node = node

    @property
    def name_attr(self) -> str:
        return self.node.get("name")

    @property
    def text(self) -> str:
        return self.node.text


class HostProperties:
    def __init__(self, node):
        self.node = node

    @property
    def tag(self) -> list:
        return [Tag(i) for i in self.node.findall('tag')]

    @property
    def host_end(self) -> str:
        _dict = self.dict_tags
        return _dict.get("HOST_END")

    @property
    def mac_address(self) -> str:
        _dict = self.dict_tags
        return _dict.get("mac-address", "")

    @property
    def operating_system(self) -> str:
        _dict = self.dict_tags
        return _dict.get("operating-system", None)

    @property
    def host_ip(self) -> str:
        _dict = self.dict_tags

        return _dict.get("host-ip", None)

    @property
    def host_fqdn(self) -> str:
        _dict = self.dict_tags
        return _dict.get("host-fqdn", None)

    @property
    def host_rdns(self) -> str:
        _dict = self.dict_tags
        return _dict.get("host-rdns", None)

    @property
    def dict_tags(self):
        host_tags = {}
        for t in self.node:
            host_tags.setdefault(t.attrib.get('name'), t.text)
        return host_tags


class ReportHost:
    def __init__(self, node):
        self.node = node

    @property
    def name(self) -> str:
        return self.node.get("name")

    @property
    def host_properties(self) -> HostProperties:
        return HostProperties(self.node.find("HostProperties"))

    @property
    def report_items(self) -> List[ReportItem]:
        return [ReportItem(i) for i in self.node.findall("ReportItem")]


class Report:

    def __init__(self, node):
        self.node = node

    @property
    def name_attr(self) -> str:
        return self.node.get("name")

    @property
    def report_hosts(self) -> List[ReportHost]:
        return [ReportHost(i) for i in self.node.findall('ReportHost')]
