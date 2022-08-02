"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from urllib.parse import urlsplit
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
        scan_type = parser.scantype
        for result in parser.results:
            self.new_structure(result, scan_type)

    def new_structure(self, result, scan_type):
        source_file = result.target
        host_id = self.createAndAddHost(source_file)
        for misconfiguration in result.misconfigurations:
            self.create_vuln_dockerfile(misconfiguration, host_id)
        for vulneravilty in result.vulnerabilities:
            self.create_vuln_image(vulneravilty, host_id)

    def create_vuln_image(self, vulneravilty, host_id):
        ref = vulneravilty.references
        if vulneravilty.cvss:
            cvss3 = {
                "base_score": vulneravilty.cvss.v3score,
                "vector_string": vulneravilty.cvss.v3score
            }
            cvss2 = {
                "base_score": vulneravilty.cvss.v2score,
                "vector_string": vulneravilty.cvss.v2score
            }
            ref.append(cvss3)
            ref.append(cvss2)
        self.createAndAddVulnToHost(
            host_id,
            name=vulneravilty.name,
            desc=vulneravilty.description,
            severity=vulneravilty.severity,
            ref=vulneravilty.references,
            cve=vulneravilty.name
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

def createPlugin(ignore_info=False, hostname_resolution=True):
    return TrivyJsonPlugin(ignore_info=ignore_info, hostname_resolution=hostname_resolution)
