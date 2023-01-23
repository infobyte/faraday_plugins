"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from urllib.parse import urlsplit
import ipaddress

from lxml import etree

from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.repo.acunetix.DTO import Acunetix, Scan
from json import loads

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"

from faraday_plugins.plugins.repo.acunetix360.DTO import Acunetix360JsonParser


class Acunetix360Plugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Acunetix360"
        self.name = "Acunetix360 Output Plugin"
        self.plugin_version = "0.1"
        self.version = "9"
        self.json_keys = {'Target', "Vulnerabilities", "Generated"}
        self.framework_version = "1.0.0"
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        parser = Acunetix360JsonParser(loads(output))
        h_id = self.createAndAddHost(self.resolve_hostname(parser.target.url))
        for vuln in parser.vulnerabilities:
            s_id = self.createAndAddServiceToHost(
                host_id=h_id,
                ports="443",
                name="/"+vuln.url.split('/')[1]
            )
            references = [
            ]
            if vuln.classification.iso:
                references.append(vuln.classification.iso)
            if vuln.classification.capec:
                references.append(vuln.classification.capec)
            if vuln.classification.hipaa:
                references.append(vuln.classification.hipaa)
            if vuln.classification.pci:
                references.append(vuln.classification.pci)
            if vuln.classification.wasc:
                references.append(vuln.classification.wasc)
            if vuln.classification.asvs:
                references.append(vuln.classification.asvs)
            if vuln.classification.nistsp:
                references.append(vuln.classification.nistsp)
            if vuln.classification.disastig:
                references.append(vuln.classification.disastig)
            resolution = vuln.remedial_actions + "\n" + vuln.remedial_procedure
            data = vuln.impact + "\n POC: " + vuln.proof_of_concept

            cvss3 = {}
            if vuln.classification.cvss31:
                cvss3['vector_string'] = vuln.classification.cvss31
            elif vuln.classification.cvss:
                cvss3['vector_string'] = vuln.classification.cvss
            self.createAndAddVulnWebToService(
                host_id=h_id,
                service_id=s_id,
                name=vuln.name,
                desc=vuln.description,
                ref=references,
                severity=vuln.severity,
                resolution=resolution,
                data=data,
                external_id="Acunetix360-"+vuln.external_id,
                tags=vuln.tags,
                method=vuln.request.method,
                request=vuln.request.content,
                response=vuln.response,
                cwe=vuln.classification.cwe,
                cvss3=cvss3
            )



def createPlugin(*args, **kwargs):
    return Acunetix360Plugin(*args, **kwargs)
