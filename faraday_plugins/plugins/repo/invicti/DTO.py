from typing import List


class Cvss3:
    def __init__(self, node):
        self.node = node

    @property
    def vector(self) -> str:
        return self.node.find('vector').text


class Reference:
    def __init__(self, node):
        self.node = node

    @property
    def owasp(self) -> str:
        return self.node.find('owasp').text

    @property
    def wasc(self) -> str:
        return self.node.find('wasc').text

    @property
    def cwe(self) -> str:
        return self.node.find('cwe').text

    @property
    def capec(self) -> str:
        return self.node.find('capec').text

    @property
    def pci32(self) -> str:
        return self.node.find('pci32').text

    @property
    def hipaa(self) -> str:
        return self.node.find('hipaa').text

    @property
    def owasppc(self) -> str:
        return self.node.find('owasppc').text

    @property
    def cvss3(self) -> Cvss3:
        return Cvss3(self.node.find("cvss31"))


class Request:
    def __init__(self, node):
        self.node = node

    @property
    def method(self) -> str:
        return self.node.find("method").text

    @property
    def content(self) -> str:
        return self.node.find("content").text


class Response:
    def __init__(self, node):
        self.node = node

    @property
    def content(self) -> str:
        return self.node.find("content").text


class Vulnerability:
    def __init__(self, node):
        self.node = node

    @property
    def look_id(self) -> str:
        return self.node.find('LookupId').text

    @property
    def url(self) -> str:
        return self.node.find("url").text

    @property
    def name(self) -> str:
        return self.node.find('name').text

    @property
    def severity(self) -> str:
        sv = self.node.find('severity').text
        if sv == "BestPractice":
            sv = "Information"
        return sv

    @property
    def confirmed(self) -> str:
        return self.node.find('confirmed').text

    @property
    def description(self) -> str:
        return self.node.find('description').text

    @property
    def http_request(self) -> Request:
        return Request(self.node.find("http-request"))

    @property
    def http_response(self) -> Response:
        return Response(self.node.find("http-response"))

    @property
    def impact(self) -> str:
        return self.node.find("impact").text

    @property
    def remedial_actions(self) -> str:
        return self.node.find("remedial-actions").text

    @property
    def remedial_procedure(self) -> str:
        return self.node.find("remedial-procedure").text

    @property
    def classification(self) -> Reference:
        return Reference(self.node.find("classification"))


class Target:
    def __init__(self, node):
        self.node = node

    @property
    def scan_id(self) -> str:
        return self.node.find("scan-id").text

    @property
    def url(self) -> str:
        return self.node.find("url").text


class Invicti:
    def __init__(self, node):
        self.node = node

    @property
    def target(self) -> Target:
        return Target(self.node.find('target'))

    @property
    def vulnerabilities(self) -> List[Vulnerability]:
        return [Vulnerability(i) for i in self.node.findall('vulnerabilities/vulnerability')]
