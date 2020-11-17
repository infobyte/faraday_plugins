"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import socket
import json
from urllib.parse import urlparse
from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat
from faraday_plugins.plugins.plugins_utils import resolve_hostname

__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class NucleiJsonParser:

    def __init__(self, json_output):
        self.list_to_vulns = json_output.split("\n")


class NucleiPlugin(PluginMultiLineJsonFormat):
    """ Handle the Nuclei tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self):
        super().__init__()
        self.id = "nuclei"
        self.name = "Nuclei"
        self.plugin_version = "0.1"
        self.version = "0.0.1"
        self.json_keys = {"matched", "template"}

    def parseOutputString(self, output, debug=False):
        parser = NucleiJsonParser(output)
        matched_list = []
        matched_json = {}
        for vuln in parser.list_to_vulns:
            if vuln != '':
                json_vuln = json.loads(vuln)
                matched = json_vuln.get('matched', None)
                
                if matched is not None:
                    url_parser = urlparse(matched)
                    url_scheme = f'{url_parser.scheme}://{url_parser.hostname}'

                    if url_scheme in matched_list:
                        matched_json[url_scheme].append(json_vuln)
                    else:
                        matched_list.append(url_scheme)
                        matched_json[url_scheme] = [json_vuln]

        for url in matched_list:
            url_data = urlparse(url)
            url_name = url_data.hostname
            url_protocol = url_data.scheme
            ip = resolve_hostname(url_name)
            host_id = self.createAndAddHost(
                name=ip,
                hostnames=[url_name])
            port = 80
            if url_parser.scheme == 'https':
                port = 443

            service_id = self.createAndAddServiceToHost(
                host_id,
                name=url_name,
                ports=port,
                protocol=url_protocol,
                status='open',
                version='',
                description='')

            for info_vuln in matched_json[url]:
                desc = f'{info_vuln.get("template", None)} - {info_vuln.get("author", None)}'

                self.createAndAddVulnWebToService(
                    host_id,
                    service_id,
                    name=info_vuln.get('matcher_name', "Nuclei"),
                    desc=desc,
                    ref=None,
                    severity=info_vuln.get('severity', ""),
                    website=url,
                    request=info_vuln.get('request', None),
                    response=info_vuln.get('response', None),
                    method=info_vuln.get('type', None),
                    data=info_vuln.get('name', None))


def createPlugin():
    return NucleiPlugin()



