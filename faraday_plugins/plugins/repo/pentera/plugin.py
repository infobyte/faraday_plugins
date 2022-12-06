"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from json import loads

from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.repo.pentera.DTO import PenteraJsonParser

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"





class PenteraJsonPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Pentera_Json"
        self.name = "Pentera Json Output Plugin"
        self.plugin_version = "1.0.0"
        self.version = "2.11.1"
        self.framework_version = "1.0.0"
        self.options = None
        self._temp_file_extension = "json"
        self.json_keys = {'vulnerabilities', 'hosts'}

    @staticmethod
    def pentera_to_severity_level(pentera_score):
        pentera_ranges = [(0.0, 0.01, 'info'),
                          (0.01, 2.5, 'low'),
                          (2.5, 4.5, 'med'),
                          (5, 7.49, 'high'),
                          (7.5, 10.1, 'critical')]
        for (lower, upper, severity) in pentera_ranges:
            if lower <= pentera_score < upper:
                return severity

    def parseOutputString(self, output):
        """
        This method will discard the output the shell sends, it will read it
        from the json where it expects it to be present.
        """

        parser = PenteraJsonParser(loads(output))
        host_dict = {}

        for host in parser.hosts:
            host_id = self.createAndAddHost(
                name=host.name,
                os=host.os,
                hostnames=[host.hostname]
            )
            host_dict[host.host_id] = {}
            for service in host.services:
                service_id = self.createAndAddServiceToHost(
                    host_id=host_id,
                    name=service.name,
                    protocol=service.protocol,
                    ports=service.port,
                    status=service.status
                )
                host_dict[host.host_id][service.port] = [host_id, service_id]
        for vuln in parser.vulneravilities:
            try:
                self.createAndAddVulnToService(
                    host_id=host_dict[vuln.host_id][vuln.port][0],
                    service_id=host_dict[vuln.host_id][vuln.port][1],
                    name=vuln.name,
                    desc=vuln.description,
                    severity=self.pentera_to_severity_level(vuln.severity),
                    resolution=vuln.resolution,
                    data=vuln.data,
                    external_id=vuln.external_id,
                    cve=vuln.cve
                )
            except KeyError:
                if "host" in vuln.found_on.lower():
                    host = vuln.found_on.lower().replace("host:", "").strip().split(",")[0]
                else:
                    host = "NOT-PROVIDED"
                host_id = self.createAndAddHost(
                    name=host,
                )
                self.createAndAddVulnToHost(
                    host_id=host_id,
                    name=vuln.name,
                    desc=vuln.description,
                    severity=self.pentera_to_severity_level(vuln.severity),
                    resolution=vuln.resolution,
                    data=vuln.data,
                    external_id=vuln.external_id,
                    cve=vuln.cve
                )


def createPlugin(*args, **kwargs):
    return PenteraJsonPlugin(*args, **kwargs)
