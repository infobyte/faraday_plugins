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
__email__ = "gmarintez@faradaysec.com"
__status__ = "Development"


class Crowdstrike(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Crowdstrike_Json"
        self.name = "Crowdstrike JSON Output Plugin"
        self.plugin_version = "1"
        self.version = "1"
        self.json_keys = {'host_id', 'host_type'}
        self.framework_version = "1.0.0"
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        parser = loads(output)
        for site in parser:
            site_name = site.get('site_name')
            hostname = site.get('hostname')
            host_tags = site.get('host_tags')
            os_version = site.get('os_version')
            host_id = self.createAndAddHost(
                name=site_name,
                os=os_version,
                hostnames=hostname,
                tags=host_tags
            )
            cve = site.get('cve_id')
            severity = site.get('severity').lower()
            cvss_vector = site.get('vector')
            references = [site.get('references')]
            vuln = site.get('cve_description')
            remedations = []
            for rr in site.get('recommended_remediations', []):
                remedations.append(rr.get('detail'))
            cvss3 = {}
            cvss2 = {}
            if float(site.get('cvss_version', '0')) > 2:
                cvss3['vector_string'] = cvss_vector
            else:
                cvss2['vector_string'] = cvss_vector
            evaluation_logic = ''
            for evaluation in site.get('evaluation_logic', []):
                result = []
                for item in evaluation.get('items', []):
                    result.append(item.get('comparison_result'))
                evaluation_logic += f'Evalutaion: {evaluation.get("title")}\n\tResults: {" ".join(result)}\n'
            self.createAndAddVulnToHost(
                host_id=host_id,
                name=vuln[:50],
                desc=vuln,
                severity=severity,
                cve=cve,
                cvss3=cvss3,
                cvss2=cvss2,
                ref=references,
                data=evaluation_logic
            )


def createPlugin(*args, **kwargs):
    return Crowdstrike(*args, **kwargs)
