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
        if not self.node:
            return ''
        return self.node.get('use_ssl', '')

    @property
    def tags(self) -> list:
        if not self.node:
            return ['']
        return self.node.get('tags', [''])

    def cvss_score(self) -> str:
        return self.node.get('cvss_score')

    @property
    def cvss2_vector(self) -> str:
        return self.node.get('cvss2', '')

    @property
    def cvss3_vector(self) -> str:
        return self.node.get('cvss3', '')


class Info:
    def __init__(self, node):
        self.node = node

    @property
    def host(self) -> str:
        if not self.node:
            return ''
        return self.node.get('host', '')

    @property
    def start_url(self) -> str:
        if not self.node:
            return ''
        return self.node.get('start_url', '')

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
