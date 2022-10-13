import re
from collections import defaultdict

from faraday_plugins.plugins.plugin import PluginBase

class RDPScanPlugin(PluginBase):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "rdpscan"
        self.id = "rdpscan"
        self.name = "rdpscan"
        self._command_regex = re.compile(r'^(sudo rdpscan|rdpscan|\.\/rdpscan)\s+.*?')

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


def createPlugin(*args, **kwargs):
    return RDPScanPlugin(*args, **kwargs)
