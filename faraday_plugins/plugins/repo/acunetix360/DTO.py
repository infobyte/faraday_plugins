from typing import List
import re

import bs4

CLEAN = re.compile("<.*?>")

def clean_external_references(external_ref) -> List[str]:
    data = bs4.BeautifulSoup(external_ref).find_all("a")
    refs = []
    for i in data:
        refs.append(i.get("href"))
    return refs


class Classification:
    def __init__(self, node):
        self.node = node

    @property
    def iso(self) -> str:
        iso = self.node.get('Iso27001', "")
        if iso:
            return "Iso27001-" + iso
        else:
            return ""

    @property
    def capec(self) -> str:
        capec = self.node.get('Capec', "")
        if capec:
            return "Capec-" + capec
        else:
            return ""

    @property
    def cvss(self) -> str:
        if self.node.get('Cvss'):
            return self.node.get('Cvss').get("Vector", "")
        return ""

    @property
    def cvss31(self) -> str:
        if self.node.get('Cvss31'):
            return self.node.get('Cvss31').get("Vector", "")
        return ""

    @property
    def cwe(self) -> str:
        cwe = self.node.get('Cwe', "")
        if cwe:
            return "CWE-" + cwe
        else:
            return ""

    @property
    def hipaa(self) -> str:
        hippa = self.node.get('Hipaa', "")
        if hippa:
            return "Hipaa-" + hippa
        else:
            return ""

    @property
    def owasp(self) -> str:
        owasp = self.node.get('Owasp', "")
        if owasp:
            return "Owasp-" + owasp
        else:
            return ""

    @property
    def pci(self) -> str:
        pci = self.node.get('Pci32', "")
        if pci:
            return "Pci32-" + pci
        else:
            return ""

    @property
    def wasc(self) -> str:
        wasc = self.node.get('Wasc', "")
        if wasc:
            return "Wasc-" + wasc
        else:
            return ""

    @property
    def asvs(self) -> str:
        asvs = self.node.get('Asvs40', "")
        if asvs:
            return "Asvs40-" + asvs
        else:
            return ""

    @property
    def nistsp(self) -> str:
        nistsp = self.node.get('Nistsp80053', "")
        if nistsp:
            return "Nistsp80053-" + nistsp
        else:
            return ""

    @property
    def disastig(self) -> str:
        disastig = self.node.get('DisaStig', "")
        if disastig:
            return "DisaStig-" + disastig
        else:
            return ""


class Request:
    def __init__(self, node):
        self.node = node

    @property
    def method(self) -> str:
        return self.node.get("Method", "")

    @property
    def content(self) -> str:
        return self.node.get("Content", "")


class Vulnerability:
    def __init__(self, node):
        self.node = node

    @property
    def name(self) -> str:
        return self.node.get('Name', "")

    @property
    def confirmed(self) -> bool:
        return self.node.get('Confirmed', False)

    @property
    def description(self) -> str:
        return CLEAN.sub("", self.node.get('Description', "The tool did not provide a description"))

    @property
    def remedial_procedure(self) -> str:
        return CLEAN.sub("", self.node.get("RemedialProcedure",""))

    @property
    def severity(self) -> str:
        return self.node.get('Severity', "unclassified")

    @property
    def impact(self) -> str:
        return CLEAN.sub("", self.node.get('Impact', ""))

    @property
    def tags(self) -> List[str]:
        return self.node.get("Tags", [])

    @property
    def classification(self) -> Classification:
        return Classification(self.node.get("Classification", {}))

    @property
    def external_id(self) -> str:
        return self.node.get("LookupId", "")

    @property
    def remedial_actions(self) -> str:
        return CLEAN.sub("", self.node.get('RemedialActions', ""))

    @property
    def proof_of_concept(self) -> str:
        return CLEAN.sub("", self.node.get('ProofOfConcept', ""))

    @property
    def external_references(self) -> List[str]:
        return clean_external_references(self.node.get('ExternalReferences', ""))

    @property
    def request(self) -> Request:
        return Request(self.node.get('Request', {}))

    @property
    def response(self) -> str:
        return self.node.get('Response', {}).get("Content", "")

    @property
    def url(self) -> str:
        return self.node.get('Url', "")


class Target:
    def __init__(self, node):
        self.node = node

    @property
    def url(self) -> str:
        return self.node.get('Url', "")


class Acunetix360JsonParser:
    def __init__(self, node):
        self.node = node

    @property
    def target(self) -> Target:
        return Target(self.node.get('Target', {}))

    @property
    def vulnerabilities(self) -> List[Vulnerability]:
        return [Vulnerability(vuln) for vuln in self.node.get('Vulnerabilities', [])]
