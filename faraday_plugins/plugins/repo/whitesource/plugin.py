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


__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class WhitesourcePlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "whitesource"
        self.name = "whitesource"
        self.plugin_version = "0.1"
        self.version = "3.4.5"
        self.json_keys = {"vulnerabilities"}
        self.filter_keys = {"host"}

    def parseOutputString(self, output):
        parser = json.loads(output)
        if parser.get('vulnerabilities'):
            for vulnerability in parser['vulnerabilities']:
                cvss3 = {}
                cvss2 = {}
                if 'project' in vulnerability:
                    application_name = vulnerability.get('project')
                    host_id = self.createAndAddHost(application_name)
                    data = ''
                    for key, value in vulnerability['library'].items():
                        data += f'{key}: {value} \n'
                    refs = []
                    if "scoreMetadataVector" in vulnerability:
                        cvss3["vector_string"] = vulnerability['scoreMetadataVector']
                    if 'topFix' in vulnerability:
                        refs.append(f"URL: {vulnerability['topFix']['url']}")
                        self.createAndAddVulnToHost(host_id,
                                                    name=vulnerability['name'],
                                                    desc=vulnerability['description'],
                                                    data=data,
                                                    resolution=vulnerability['topFix']['fixResolution'],
                                                    ref=refs,
                                                    severity=vulnerability['severity'],
                                                    cve=[vulnerability['name']],
                                                    cvss2=cvss2,
                                                    cvss3=cvss3)
                    else:
                        self.createAndAddVulnToHost(host_id,
                                                    name=vulnerability['name'],
                                                    desc=vulnerability['description'],
                                                    data=data,
                                                    ref=refs,
                                                    severity=vulnerability['severity'],
                                                    cvss2=cvss2,
                                                    cvss3=cvss3)
                elif 'namespace' in vulnerability:
                    host_id = self.createAndAddHost(vulnerability['namespace'])
                    service_id = self.createAndAddServiceToHost(
                        host_id,
                        vulnerability['featurename'],
                        ports=0
                    )
                    self.createAndAddVulnToService(
                        host_id,
                        service_id,
                        name=vulnerability['vulnerability'],
                        desc=vulnerability['description'],
                        ref=[vulnerability['link']],
                        severity=vulnerability['severity'],
                        cve=[vulnerability['vulnerability']]
                    )

                elif 'package' in vulnerability:
                    host_id = self.createAndAddHost(vulnerability['feed_group'])
                    service_id = self.createAndAddServiceToHost(
                        host_id,
                        vulnerability['package'],
                        ports=0
                    )
                    self.createAndAddVulnToService(
                        host_id,
                        service_id,
                        name=f'{vulnerability["vuln"]} {vulnerability["package_name"]}',
                        ref=[vulnerability['url']],
                        severity=vulnerability['severity'],
                        cve=[vulnerability['vuln']]
                    )


def createPlugin(*args, **kwargs):
    return WhitesourcePlugin(*args, **kwargs)
