from typing import List


class InfoVul:
    def __init__(self, node):
        self.node = node

    @property
    def vt_id(self) -> str:
        if not self.node:
            return ''
        return self.node.get('vt_id', '')

    @property
    def request(self) -> str:
        if not self.node:
            return ''
        return self.node.get('request', '')


class Vulnerabilities:
    def __init__(self, node):
        self.node = node

    @property
    def info(self) -> InfoVul:
        return InfoVul(self.node.get('info'))

    @property
    def response(self) -> str:
        if not self.node:
            return ''
        return self.node.get('response', '')


class VulnerabilityTypes:
    def __init__(self, node):
        self.node = node

    @property
    def vt_id(self) -> str:
        if not self.node:
            return ''
        return self.node.get('vt_id', '')

    @property
    def name(self) -> str:
        if not self.node:
            return ''
        return self.node.get('name', '')

    @property
    def description(self) -> str:
        if not self.node:
            return ''
        return self.node.get('description', '')

    @property
    def severity(self) -> int:
        return self.node.get('severity', '')

    @property
    def recommendation(self) -> str:
        if not self.node:
            return ''
        return self.node.get('recommendation', '')

    @property
    def app_id(self) -> str:
        if not self.node:
            return ''
        return self.node.get('app_id', '')

    @property
    def use_ssl(self) -> bool:
        return self.node.get('use_ssl', '')


class Info:
    def __init__(self, node):
        self.node = node

    @property
    def host(self) -> str:
        if not self.node:
            return ''
        return self.node.get('host', '')


class Scan:
    def __init__(self, node):
        self.node = node

    @property
    def info(self) -> Info:
        return Info(self.node.get('info'))

    @property
    def vul_types(self) -> List[VulnerabilityTypes]:
        return [VulnerabilityTypes(i) for i in self.node.get('vulnerability_types', [])]

    @property
    def vulnerabilities(self) -> List[Vulnerabilities]:
        return [Vulnerabilities(i) for i in self.node.get('vulnerabilities', [])]


class Export:
    def __init__(self, node):
        self.node = node

    @property
    def scans(self) -> List[Scan]:
        return [Scan(i) for i in self.node.get('scans', [])]

    @property
    def lang(self) -> str:
        if not self.node:
            return ''
        return self.node.get('scans', '')


class AcunetixJsonParser:
    def __init__(self, node):
        self.node = node

    @property
    def export(self) -> Export:
        return Export(self.node.get('export'))