"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from urllib.parse import urlparse


__author__ = "Nicolas Rebagliati"
__copyright__ = "Copyright (c) 2019, Infobyte LLC"
__credits__ = ["Nicolas Rebagliati"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Nicolas Rebagliati"
__email__ = "nrebagliati@infobytesec.com"
__status__ = "Development"

from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.plugins_utils import resolve_hostname


class WPScanJsonParser:

    def __init__(self, json_output):
        self.json_data = json.loads(json_output)

    def parse_url(self, url):
        # Strips protocol and gets hostname from URL.

        url_parse = urlparse(url)
        protocol = url_parse.scheme
        hostname = url_parse.netloc
        port = url_parse.port

        if protocol == 'https':
            port = 443
        elif protocol == 'http':
            if not port:
                port = 80
        address = resolve_hostname(hostname)
        return {'protocol': protocol, 'hostname': hostname, 'port': port, 'address': address}



class WPScanPlugin(PluginJsonFormat):
    """ Handle the WPScan tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self):
        super().__init__()
        self.id = "wpscan"
        self.name = "WPscan"
        self.plugin_version = "0.2"
        self.version = "3.4.5"
        self.json_keys = {"target_url", "effective_url", "interesting_findings"}

    def parseOutputString(self, output, debug=False):
        parser = WPScanJsonParser(output)
        url_data = parser.parse_url(parser.json_data['target_url'])
        host_id = self.createAndAddHost(url_data['address'], hostnames=[url_data['hostname']])
        service_id = self.createAndAddServiceToHost(
            host_id,
            "WordPress",
            url_data['protocol'],
            ports=[url_data['port']],
            status='open',
            version='',
            description='')
        for user, data in parser.json_data.get('users', {}).items():
            self.createAndAddCredToService(host_id, service_id, user, "")
        main_theme = parser.json_data.get("main_theme", {})
        for vuln in main_theme.get("vulnerabilities", []):
            wpvulndb = ",".join(vuln['references'].get('wpvulndb', []))
            self.createAndAddVulnWebToService(host_id, service_id, vuln['title'], ref=vuln['references'].get('url', []),
                                              severity='unclassified', external_id=wpvulndb)
        for plugin, plugin_data in parser.json_data.get("plugins", {}).items():
            for vuln in plugin_data['vulnerabilities']:
                wpvulndb = ",".join(vuln['references'].get('wpvulndb', []))
                self.createAndAddVulnWebToService(host_id, service_id, f"{plugin}: {vuln['title']}",
                                                  ref=vuln['references'].get('url', []),
                                                  severity='unclassified', external_id=wpvulndb)
        for vuln in parser.json_data.get("interesting_findings", []):
            if vuln['to_s'].startswith('http'):
                vuln_name = f"{vuln['type']}: {vuln['to_s']}"
            else:
                vuln_name = vuln['to_s']
            self.createAndAddVulnWebToService(host_id, service_id, vuln_name, ref=vuln['references'].get('url', []),
                                              severity='unclassified')


def createPlugin():
    return WPScanPlugin()
