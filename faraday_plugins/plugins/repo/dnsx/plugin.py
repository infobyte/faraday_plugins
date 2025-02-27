
import json

from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat

__author__ = "six2dez"
__version__ = "0.0.1"
__maintainer__ = "six2dez"
__email__ = "six2dez@gmail.com"
__status__ = "Development"


class DNSXPlugin(PluginMultiLineJsonFormat):
    """
    Plugin to parse dnsx JSON output (one JSON object per line).
    """

    def __init__(self, ignore_info=False, hostname_resolution=True, vuln_tag=None, service_tag=None, host_tag=None):
        super().__init__(ignore_info=ignore_info)
        self.id = "dnsx"
        self.name = "DNSX Multiline JSON Plugin"
        self.plugin_version = "1.2.2"
        self.json_keys = {"host", "ttl", "timestamp"}
        self.vuln_tag = vuln_tag
        self.service_tag = service_tag
        self.host_tag = host_tag

    def parseOutputString(self, output, debug=False):
        lines = output.strip().splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host", "")
            if not host:
                continue

            a_records = data.get("a", [])
            aaaa_records = data.get("aaaa", [])

            # If no IPs are returned, record the hostname-only host
            if not a_records and not aaaa_records:
                h_id = self.createAndAddHost(name=host)
                if self.host_tag:
                    self.createAndAddNoteToHost(h_id, name="Host Tag", text=self.host_tag)
            else:
                # For each IP, create a host and add the hostname as a host alias
                for ip_addr in a_records + aaaa_records:
                    h_id = self.createAndAddHost(name=ip_addr, hostnames=[host])
                    if self.host_tag:
                        self.createAndAddNoteToHost(h_id, name="Host Tag", text=self.host_tag)
                    if self.service_tag:
                        self.createAndAddNoteToHost(h_id, name="Service Tag", text=self.service_tag)
                    if self.vuln_tag:
                        self.createAndAddNoteToHost(h_id, name="Vulnerability Tag", text=self.vuln_tag)


def createPlugin(ignore_info=False, hostname_resolution=True, vuln_tag=None, service_tag=None, host_tag=None):
    return DNSXPlugin(ignore_info=ignore_info, hostname_resolution=hostname_resolution, vuln_tag=vuln_tag, service_tag=service_tag, host_tag=host_tag)
