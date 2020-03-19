"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat
from urllib.parse import urlparse


__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2019, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class SourceclearJsonParser:
    def __init__(self, json_output):
        self.json_data = json.loads(json_output)

    def parse_url(self, url):
        url_parse = urlparse(url)
        protocol = url_parse.scheme
        hostname = url_parse.netloc
        port = url_parse.port

        if protocol == 'https':
            port = 443
        elif protocol == 'http':
            if not port:
                port = 80
        return {'protocol': protocol, 'hostname': hostname, 'port': port}


class SourceclearPlugin(PluginJsonFormat):
    """ Handle the Sourceclear tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self):
        super().__init__()
        self.id = "sourceclear"
        self.name = "Sourceclear"
        self.plugin_version = "0.1"
        self.version = "0.0.1"
        self.json_keys = {"metadata", "records"}

    def parseOutputString(self, output, debug=False):
        parser = SourceclearJsonParser(output)
        vulns = {}
        for records in parser.json_data['records']:
            vulns = records['vulnerabilities']
            h_id = self.createAndAddHost(name='0.0.0.0', scan_template=records['metadata']['recordType'])

        for vuln in vulns:
            v_name = vuln['title']
            v_desc = vuln['overview']
            v_ref = "CVSS: {}".format(vuln['cvssScore'])
            v_data = vuln['libraries']
            v_website = vuln['_links']['html']
            url_data = parser.parse_url(v_website)
            s_id = self.createAndAddServiceToHost(h_id, "Sourceclear", protocol=url_data['protocol'],
                                                  ports=url_data['port'], status='open')
            self.createAndAddVulnWebToService(h_id, s_id, name=v_name, desc=v_desc, ref=[v_ref], data=v_data,
                                              website=v_website)


def createPlugin():
    return SourceclearPlugin()
