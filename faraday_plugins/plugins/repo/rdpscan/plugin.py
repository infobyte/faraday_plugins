import re
from collections import defaultdict

from faraday_plugins.plugins.plugin import PluginBase
from faraday_plugins.plugins.plugins_utils import resolve_hostname


class RDPScanPlugin(PluginBase):

    def __init__(self):
        super().__init__()
        self.identifier_tag = "rdpscan"
        self.id = "rdpscan"
        self.name = "rdpscan"
        self._command_regex = re.compile(r'rdpscan')

    def parseOutputString(self, output):
        services = defaultdict(set)
        for info in output.split('\n'):
            if info:
                ip, status, data = info.split('-', 2)
                ip = ip.strip()
                status = status.strip()
                data = data.strip()
                if status.lower() == 'unknown':
                    continue

                host_id = self.createAndAddHost(ip)
                service_id = self.createAndAddServiceToHost(
                    host_id=host_id,
                    name='rdp',
                    ports=3389,
                    protocol='tcp',
                )
                if status.lower() == 'vulnerable':
                    description = "A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'. "
                    self.createAndAddVulnToService(
                        host_id=host_id,
                        service_id=service_id,
                        name='Remote Desktop Services Remote Code Execution Vulnerability',
                        desc=description,
                        ref=['CVE-2019-0708']
                    )


        for ip_address, parsed_urls in services.items():
            hostnames = list(set([parsed_url.netloc.split(':').pop() for parsed_url in parsed_urls]))
            h_id = self.createAndAddHost(ip_address, hostnames=hostnames)
            for parsed_url in parsed_urls:
                port = parsed_url.port
                if not port:
                    if parsed_url.scheme == 'http':
                        port = 80
                    if parsed_url.scheme == 'https':
                        port = 443
                self.createAndAddServiceToHost(
                    host_id=h_id,
                    name=parsed_url.scheme,
                    ports=port,
                    protocol='tcp',
                )


def createPlugin():
    return RDPScanPlugin()
