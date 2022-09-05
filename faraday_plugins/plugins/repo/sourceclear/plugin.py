"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat
from urllib.parse import urlparse
import os


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

        if port is None:
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

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "sourceclear"
        self.name = "Sourceclear"
        self.plugin_version = "0.1"
        self.version = "0.0.1"
        self.json_keys = {"metadata", "records"}

    def parseOutputString(self, output, debug=False):
        parser = SourceclearJsonParser(output)

        for records in parser.json_data['records']:
            vulns = records['vulnerabilities']
            libraries = records['libraries']

            for vuln in vulns:
                v_name = vuln['title']
                v_desc = vuln['overview']
                v_data = vuln['libraries']
                v_website = vuln['_links']['html']
                url_data = parser.parse_url(v_website)
                for refs in vuln['libraries']:
                    ref = refs['_links']['ref']
                    num_versions = ref.find("/versions")
                    _, num_libraries = os.path.split(ref[:num_versions])
                    name_librarie = libraries[int(num_libraries)]['name']
                    version_librarie = libraries[int(num_libraries)]['versions'][0]['version']
                    host_name = f'{name_librarie}{version_librarie}'

                h_id = self.createAndAddHost(name=host_name, scan_template=records['metadata']['recordType'])
                s_id = self.createAndAddServiceToHost(h_id, "Sourceclear", protocol=url_data['protocol'],
                                                      ports=url_data['port'], status='open')
                self.createAndAddVulnWebToService(h_id, s_id, name=v_name, desc=v_desc, data=v_data,
                                                  website=v_website)


def createPlugin(*args, **kwargs):
    return SourceclearPlugin(*args, **kwargs)
