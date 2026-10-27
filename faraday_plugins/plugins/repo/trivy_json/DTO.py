class Base:
    def __init__(self, node):
        self.node = node


class Cvss(Base):
    @property
    def v2vector(self):
        return self.node.get("V2Vector")

    @property
    def v3vector(self):
        return self.node.get("V3Vector")

    @property
    def v2score(self):
        return self.node.get("V2Score")

    @property
    def v3score(self):
        return self.node.get("V3Score")


class Line(Base):

    @property
    def number(self):
        return self.node.get("Number")

    @property
    def content(self):
        return self.node.get("Content")


class Code(Base):

    @property
    def lines(self):
        if self.node.get("Lines"):
            return [Line(i) for i in self.node.get("Lines")]
        else:
            return None


class CauseMetadata(Base):

    @property
    def code(self):
        return Code(self.node.get("Code"))


class Misconfiguration(Base):

    @property
    def misconfig_type(self):
        return self.node.get("Type")

    @property
    def misconfig_id(self):
        return self.node.get("ID")

    @property
    def title(self):
        return self.node.get("Title")

    @property
    def description(self):
        description = self.node.get("Description")
        if description:
            return description
        else:
            return "Issues provided no description"

    @property
    def message(self):
        return self.node.get("Message")

    @property
    def resolution(self):
        return self.node.get("Resolution")

    @property
    def severity(self):
        return self.node.get("Severity")

    @property
    def references(self):
        return self.node.get("References")

    @property
    def cause_metadata(self):
        return CauseMetadata(self.node.get("CauseMetadata"))


class Vulnerability(Base):

    @property
    def name(self):
        return self.node.get("VulnerabilityID")

    @property
    def title(self):
        return self.node.get("Title")

    @property
    def pkgname(self):
        return self.node.get("PkgName")

    @property
    def url(self):
        return self.node.get("PrimaryURL")

    @property
    def description(self):
        description = self.node.get("Description")
        if description:
            return description
        else:
            return "Issues provided no description"

    @property
    def severity(self):
        return self.node.get("Severity")

    @property
    def cwe(self):
        return self.node.get("CweIDs")

    @property
    def cvss(self):
        cvss_node = self.node.get("CVSS") or self.node.get("cvss")
        if cvss_node:
            return Cvss(cvss_node.get("nvd") or {})
        else:
            return None

    @property
    def references(self):
        return self.node.get("References")


class Result(Base):

    @property
    def target(self):
        return self.node.get("Target")

    @property
    def misconfigurations(self):
        return [Misconfiguration(i) for i in (self.node.get("Misconfigurations") or [])]

    @property
    def vulnerability(self):
        return [Vulnerability(i) for i in (self.node.get("Vulnerabilities") or [])]

    @property
    def result_type(self):
        return self.node.get("Type")


class Metadata(Base):

    @property
    def os_family(self):
        return self.node.get("Family")

    @property
    def os_name(self):
        return self.node.get("Name")


class TrivyJsonParser(Base):

    @property
    def results(self):
        # Trivy v0.x emitted the report as a top-level JSON array of Results.
        # Trivy >= v0.20 wraps it in {"SchemaVersion": ..., "Results": [...]}.
        if isinstance(self.node, list):
            return [Result(i) for i in self.node]
        return [Result(i) for i in (self.node.get('Results') or [])]

    @property
    def scantype(self):
        if isinstance(self.node, list):
            return ""
        return self.node.get('ArtifactType')

    def metadata(self):
        if isinstance(self.node, list):
            return Metadata({})
        return Metadata(self.node.get('Metadata') or {})
