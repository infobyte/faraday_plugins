"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.repo.trivy_json.DTO import TrivyJsonParser
from json import loads

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"


class TrivyJsonPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Trivy_Json"
        self.name = "Trivy JSON Output Plugin"
        self.plugin_version = "1"
        self.version = "9"
        self.json_keys = {'SchemaVersion'}
        self.framework_version = "1.0.0"
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        parser = TrivyJsonParser(loads(output))
        scantype = parser.scantype
        for result in parser.results:
            self.new_structure(result, scantype)

    def new_structure(self, result, scantype):
        source_file = result.target
        host_id = self.createAndAddHost(source_file, os=result.result_type, description=scantype)
        for misconfiguration in result.misconfigurations:
            self.create_vuln_dockerfile(misconfiguration, host_id)
        for vulnerability in result.vulnerability:
            self.create_vuln_image(vulnerability, host_id)

    def create_vuln_image(self, vulnerability, host_id):
        ref = vulnerability.references
        cvss3 = {}
        cvss2 = {}
        if vulnerability.cvss:
            cvss3["vector_string"] = vulnerability.cvss.v3vector
            cvss3["base_score"] = vulnerability.cvss.v3score
            cvss2["vector_string"] = vulnerability.cvss.v3vector
            cvss2["base_score"] = vulnerability.cvss.v2score
        cwe = []
        if vulnerability.cwe:
            if isinstance(vulnerability.cwe, list):
                for v_cwe in vulnerability.cwe:
                    cwe.append(v_cwe)
            else:
                cwe.append(vulnerability.cwe)
        if vulnerability.title == "security flaw":
            name = vulnerability.pkgname + ":" + vulnerability.title
        elif vulnerability.title is None:
            name = vulnerability.pkgname
        else:
            name = vulnerability.title
        self.createAndAddVulnToHost(
            host_id,
            name=name,
            desc=vulnerability.description,
            severity=vulnerability.severity,
            ref=ref,
            cve=vulnerability.name,
            cvss2=cvss2,
            cvss3=cvss3,
            cwe=cwe
        )

    def create_vuln_dockerfile(self, misconfiguration, host_id):
        ref = misconfiguration.references
        data = [misconfiguration.message]
        if misconfiguration.cause_metadata.code.lines:
            for line in misconfiguration.cause_metadata.code.lines:
                data.append(f"Line {line.number}, {line.content}")
        self.createAndAddVulnToHost(
            host_id,
            name=misconfiguration.title,
            desc=misconfiguration.description,
            severity=misconfiguration.severity,
            resolution=misconfiguration.resolution,
            external_id=f"Trivy-{misconfiguration.misconfig_id}",
            ref=ref,
            data="\n".join(data)
        )


def createPlugin(*args, **kwargs):
    return TrivyJsonPlugin(*args, **kwargs)
