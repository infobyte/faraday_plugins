from typing import List

class Technicaldetails:
    def __init__(self, node):
        self.node = node

    @property
    def request(self) -> str:
        return self.node.find('Request')


class Cwe:
    def __init__(self, node):
        self.node = node

    @property
    def id_attr(self) -> str:
        return self.node.find('id')

    @property
    def text(self) -> str:
        return self.node.find('#text')


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
        return self.node.find('Descriptor')

    @property
    def score(self) -> str:
        return self.node.find('Score')

    @property
    def av(self) -> str:
        return self.node.find('AV')

    @property
    def ac(self) -> str:
        return self.node.find('AC')

    @property
    def au(self) -> str:
        return self.node.find('Au')

    @property
    def c(self) -> str:
        return self.node.find('C')

    @property
    def i(self) -> str:
        return self.node.find('I')

    @property
    def a(self) -> str:
        return self.node.find('A')

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
        return self.node.find('Descriptor')

    @property
    def score(self) -> str:
        return self.node.find('Score')

    @property
    def tempscore(self):
        return self.node.find('TempScore')

    @property
    def envscore(self):
        return self.node.find('EnvScore')

    @property
    def av(self) -> str:
        return self.node.find('AV')

    @property
    def ac(self) -> str:
        return self.node.find('AC')

    @property
    def pr(self) -> str:
        return self.node.find('PR')

    @property
    def ui(self) -> str:
        return self.node.find('UI')

    @property
    def s(self) -> str:
        return self.node.find('S')

    @property
    def c(self) -> str:
        return self.node.find('C')

    @property
    def i(self) -> str:
        return self.node.find('I')

    @property
    def a(self) -> str:
        return self.node.find('A')

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
        return self.node.find('Database')

    @property
    def url(self) -> str:
        return self.node.find('URL')


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
        return self.node.find('id')

    @property
    def color_attr(self) -> str:
        return self.node.find('color')

    @property
    def name(self) -> str:
        return self.node.find('Name')

    @property
    def modulename(self) -> str:
        return self.node.find('ModuleName')

    @property
    def details(self) -> str:
        return self.node.find('Details')

    @property
    def affects(self) -> str:
        return self.node.find('Affects')

    @property
    def parameter(self):
        return self.node.find('Parameter')

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
        return self.node.find('Severity')

    @property
    def type(self) -> str:
        return self.node.find('Type')

    @property
    def impact(self) -> str:
        return self.node.find('Impact')

    @property
    def description(self) -> str:
        return self.node.find('Description')

    @property
    def recommendation(self) -> str:
        return self.node.find('Recommendation')

    @property
    def technicaldetails(self) -> Technicaldetails:
        return Technicaldetails(self.node.find('TechnicalDetails'))

    @property
    def cwelist(self) -> Cwelist:
        return Cwelist(self.node.find('CWEList'))

    @property
    def cvelist(self):
        return self.node.find('CVEList')

    @property
    def cvss(self) -> Cvss:
        return Cvss(self.node.find('cvss'))

    @property
    def cvss3(self) -> Cvss3:
        return Cvss3(self.node.find('cvss3'))

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
        return self.node.get("StartUrl")


class Scan:
    def __init__(self, node):
        self.node = node

    @property
    def reportitems(self) -> Reportitems:
        return Reportitems(self.node.find('ReportItems'))

    @property
    def start_url(self) -> str:
        return self.node.find("StartURL")

    @property
    def crawler(self) -> Crawler:
        return Crawler(self.node.find('Crawler'))

class Acunetix:
    def __init__(self, node):
        self.node = node

    @property
    def exportedon_attr(self) -> str:
        return self.node.get('ExportedOn')

    @property
    def scan(self) -> List[Scan]:
        return [Scan(i) for i in self.node.findall('Scan', [])]
