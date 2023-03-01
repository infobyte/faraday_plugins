from typing import List
import re

class Technicaldetails:
    def __init__(self, node):
        self.node = node

    @property
    def request(self) -> str:
        if self.node in ('', None):
            return ''
        return self.node.findtext('Request', '')

    @property
    def response(self) -> str:
        if self.node in ('', None):
            return ''
        return self.node.findtext('Response', '')


class Cve:
    def __init__(self, node):
        self.node = node

    @property
    def text(self) -> str:
        if self.node in ('', None):
            return ''
        return self.node.text


class CVEList:
    def __init__(self, node):
        self.node = node

    @property
    def cve(self) -> Cve:
        if self.node is None:
            return ''
        return Cve(self.node.find('CVE'))


class Cwe:
    def __init__(self, node):
        self.node = node

    @property
    def id_attr(self) -> str:
        return self.node.attrib.get('id', '')

    @property
    def text(self) -> str:
        return self.node.text


class Cwelist:
    def __init__(self, node):
        self.node = node

    @property
    def cwe(self) -> Cwe:
        return Cwe(self.node.find('CWE'))


class Cvss:
    def __init__(self, node):
        self.node = node

    @property
    def descriptor(self) -> str:
        return self.node.findtext('Descriptor', '')

    @property
    def score(self) -> str:
        if self.node is None:
            return ''
        return self.node.findtext('Score')

    @property
    def av(self) -> str:
        return self.node.findtext('AV', '')

    @property
    def ac(self) -> str:
        return self.node.findtext('AC', '')

    @property
    def au(self) -> str:
        return self.node.findtext('Au', '')

    @property
    def c(self) -> str:
        return self.node.findtext('C', '')

    @property
    def i(self) -> str:
        return self.node.findtext('I', '')

    @property
    def a(self) -> str:
        return self.node.findtext('A', '')

    @property
    def e(self):
        return self.node.find('E')

    @property
    def rl(self):
        return self.node.find('RL')

    @property
    def rc(self):
        return self.node.find('RC')


class Cvss3:
    def __init__(self, node):
        self.node = node

    @property
    def descriptor(self) -> str:
        return self.node.findtext('Descriptor', '')

    @property
    def score(self) -> str:
        return self.node.findtext('Score')

    @property
    def tempscore(self):
        return self.node.find('TempScore')

    @property
    def envscore(self):
        return self.node.find('EnvScore')

    @property
    def av(self) -> str:
        return self.node.find('AV', '')

    @property
    def ac(self) -> str:
        return self.node.find('AC', '')

    @property
    def pr(self) -> str:
        return self.node.find('PR', '')

    @property
    def ui(self) -> str:
        return self.node.find('UI', '')

    @property
    def s(self) -> str:
        return self.node.find('S', '')

    @property
    def c(self) -> str:
        return self.node.find('C', '')

    @property
    def i(self) -> str:
        return self.node.findtext('I', '')

    @property
    def a(self) -> str:
        return self.node.findtext('A', '')

    @property
    def e(self):
        return self.node.find('E')

    @property
    def rl(self):
        return self.node.find('RL')

    @property
    def rc(self):
        return self.node.find('RC')


class Reference:
    def __init__(self, node):
        self.node = node

    @property
    def database(self) -> str:
        return self.node.findtext('Database', '')

    @property
    def url(self) -> str:
        return self.node.findtext('URL', '')


class References:
    def __init__(self, node):
        self.node = node

    @property
    def reference(self) -> List[Reference]:
        return [Reference(i) for i in self.node.findall('Reference', [])]


class Reportitem:
    def __init__(self, node):
        self.node = node

    @property
    def id_attr(self) -> str:
        return self.node.findtext('id', '')

    @property
    def color_attr(self) -> str:
        return self.node.findtext('color', '')

    @property
    def name(self) -> str:
        return self.node.findtext('Name', '')

    @property
    def modulename(self) -> str:
        return self.node.findtext('ModuleName', '')

    @property
    def details(self) -> str:
        return self.node.findtext('Details', '')

    @property
    def affects(self) -> str:
        return self.node.findtext('Affects', '')

    @property
    def parameter(self) -> str:
        return self.node.findtext('Parameter')

    @property
    def aop_sourcefile(self):
        return self.node.find('AOP_SourceFile')

    @property
    def aop_sourceline(self):
        return self.node.find('AOP_SourceLine')

    @property
    def aop_additional(self):
        return self.node.find('AOP_Additional')

    @property
    def isfalsepositive(self):
        return self.node.find('IsFalsePositive')

    @property
    def severity(self) -> str:
        return self.node.findtext('Severity', '')

    @property
    def type(self) -> str:
        return self.node.findtext('Type', '')

    @property
    def impact(self) -> str:
        return self.node.findtext('Impact', '')

    @property
    def description(self) -> str:
        return self.node.findtext('Description', '')

    @property
    def recommendation(self) -> str:
        return self.node.findtext('Recommendation', '')

    @property
    def technicaldetails(self) -> Technicaldetails:
        return Technicaldetails(self.node.find('TechnicalDetails'))

    @property
    def cwelist(self) -> Cwelist:
        return Cwelist(self.node.find('CWEList'))

    @property
    def cvelist(self):
        return CVEList(self.node.find('CVEList'))

    @property
    def cvss(self) -> Cvss:
        cvss = self.node.find('CVSS')
        if not cvss:
            cvss = self.node.find('cvss')
        return Cvss(cvss)

    @property
    def cvss3(self) -> Cvss3:
        cvss = self.node.find('CVSS3')
        if not cvss:
            cvss = self.node.find('cvss3')
        return Cvss3(cvss)

    @property
    def references(self) -> References:
        return References(self.node.find('References'))


class Reportitems:
    def __init__(self, node):
        self.node = node

    @property
    def reportitem(self) -> List[Reportitem]:
        return [Reportitem(i) for i in self.node.findall('ReportItem', [])]


class Crawler:
    def __init__(self, node):
        self.node = node

    @property
    def start_url_attr(self) -> str:
        return self.node.get('StartUrl', '')


class Scan:
    def __init__(self, node):
        self.node = node

    @property
    def reportitems(self) -> Reportitems:
        return Reportitems(self.node.find('ReportItems'))

    @property
    def start_url(self) -> str:
        return self.node.findtext("StartURL", "")

    @property
    def crawler(self) -> Crawler:
        return Crawler(self.node.find('Crawler'))

    @property
    def os(self) -> str:
        if not self.node.findtext("Os", "unknown"):
            return "unknown"
        return self.node.findtext("Os", "unknown")

    @property
    def banner(self) -> str:
        if not self.node.findtext('Banner'):
            return None
        return self.node.findtext("Banner")

    @property
    def start_url_new(self) -> str:
        return self.node.findtext("", "")


class Acunetix:
    def __init__(self, node):
        self.node = node

    @property
    def exportedon_attr(self) -> str:
        return self.node.get('ExportedOn')

    @property
    def scan(self) -> List[Scan]:
        return [Scan(i) for i in self.node.findall('Scan', [])]
