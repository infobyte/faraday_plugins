"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re
import socket
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat
from urllib.parse import urlparse


__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@faradaysec.com"
__status__ = "Development"


class SnykPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Snyk"
        self.name = "Snyk"
        self.plugin_version = "1"
        self.version = "1.1260.0"
        self.json_keys = {"vulnerabilities", "projectName"}
        self.filter_keys = {"imageDigest", "host"}

    def parseOutputString(self, output):
        parser = json.loads(output)
        h_id = self.createAndAddHost(
            name=parser.get('projectName'),
            os=parser.get('plataform', 'unknown'),
        )
        for vulnerability in parser.get('vulnerabilities', []):
            vuln = {
                'name': vulnerability['title'],
                'desc': vulnerability['description'],
                'severity': vulnerability['severity'],
                'cve': vulnerability.get('identifiers', {}).get('cve', ''),
                'cwe': vulnerability.get('identifiers', {}).get('cwe', ''),
                'ref': [ref.get('url') for ref in vulnerability.get('references', [])],
                'external_id': vulnerability.get('id', '')
            }
            if vulnerability.get('CVSSv3'):
                vuln['cvss3'] = {'vector_string': vulnerability.get('CVSSv3')}
            self.createAndAddVulnToHost(
                host_id=h_id,
                **vuln
            )


def createPlugin(*args, **kwargs):
    return SnykPlugin(*args, **kwargs)
