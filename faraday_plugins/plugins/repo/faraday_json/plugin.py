"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@faradaysec.com"
__status__ = "Development"


class FaradayJsonPlugin(PluginJsonFormat):
    '''
    This is a plugin for Faraday's Pluin output
    '''

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Faraday_JSON"
        self.name = "Faraday Json"
        self.plugin_version = "1.0.0"
        self.json_keys = {'hosts', 'command'}

    def parseOutputString(self, output):
        parser = json.loads(output)
        for host in parser.pop('hosts'):
            services = host.pop('services', [])
            vulns = host.pop('vulnerabilities', [])
            host['name'] = host.pop('ip', '')
            host.pop('credentials', '')
            host_id = self.createAndAddHost(**host)
            for vuln in vulns:
                vuln['ref'] = vuln.pop('refs', '')
                vuln.pop('type', '')
                vuln.pop('run_date', '')
                self.createAndAddVulnToHost(host_id=host_id, **vuln)
            for service in services:
                vulns = service.pop('vulnerabilities', [])
                service['ports'] = service.pop('port', '')
                service.pop('credentials', '')
                service_id = self.createAndAddServiceToHost(host_id=host_id, **service)
                for vuln in vulns:
                    vuln['ref'] = vuln.pop('refs', '')
                    vuln.pop('type', '')
                    vuln.pop('run_date', '')
                    self.createAndAddVulnWebToService(host_id=host_id, service_id=service_id, **vuln)


def createPlugin(*args, **kwargs):
    return FaradayJsonPlugin(*args, **kwargs)
