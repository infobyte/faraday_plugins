from typing import List
import re

from faraday_plugins.plugins.plugins_utils import CVE_regex

CVE_WITH_P_regex = re.compile(r'\(CVE-\d{4}-\d{4,7}\)')


class Service:
    def __init__(self, node):
        self.node = node

    @property
    def name(self):
        return self.node.get("name", "")

    @property
    def port(self):
        return self.node.get("port", "")

    @property
    def protocol(self):
        return self.node.get("transport", "")

    @property
    def status(self) -> str:
        return self.node.get("status", "")


class Host:
    def __init__(self, node):
        self.node = node

    @property
    def host_id(self) -> str:
        return self.node.get("id", "")

    @property
    def hostname(self) -> str:
        return self.node.get("hostname", "")

    @property
    def name(self) -> str:
        return self.node.get("ip", "")

    @property
    def os(self) -> str:
        return self.node.get("os_name", "")

    @property
    def services(self) -> List[Service]:
        return [Service(ser) for ser in self.node.get("services", "")]


class Vulneravility:
    def __init__(self, node):
        self.node = node

    @property
    def external_id(self) -> str:
        return "Pentera-"+self.node.get("id", "")

    @property
    def name(self) -> str:
        return CVE_WITH_P_regex.sub("", self.node.get("name", "")).strip()

    @property
    def description(self) -> str:
        desc = self.node.get("summary", "")
        if not desc:
            desc = self.name
        return desc

    @property
    def found_on(self) -> str:
        return self.node.get("found_on", "")

    @property
    def host(self) -> str:
        return self.node.get("target", "")

    @property
    def host_id(self) -> str:
        return self.node.get("target_id", "")

    @property
    def port(self) -> str:
        return self.node.get("port", "")

    @property
    def protocol(self) -> str:
        return self.node.get("protocol", "")

    @property
    def severity(self) -> float:
        return float(self.node.get("severity", 0))

    @property
    def data(self) -> str:
        return self.node.get("insight", "")

    @property
    def resolution(self) -> str:
        return self.node.get("remediation", "")

    @property
    def cve(self) -> str:
        return CVE_regex.sub("", self.node.get("name", "")).strip()
class Achievment:
    def __init__(self, node):
        self.node = node


class Meta:
    def __init__(self, node):
        self.node = node


class PenteraJsonParser:
    def __init__(self, node):
        self.node = node

    @property
    def meta(self) -> Meta:
        return Meta(self.node.get('meta', {}))

    @property
    def achievements(self) -> List[Achievment]:
        return [Achievment(i) for i in self.node.get('Achievement', [])]

    @property
    def vulneravilities(self) -> List[Vulneravility]:
        return [Vulneravility(i) for i in self.node.get('vulnerabilities', [])]

    @property
    def hosts(self) -> List[Host]:
        return [Host(i) for i in self.node.get('hosts')]
