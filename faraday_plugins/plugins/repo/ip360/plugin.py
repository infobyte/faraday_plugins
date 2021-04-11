"""
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import csv
from io import StringIO
from faraday_plugins.plugins.plugin import PluginBase


def calculate_severity(number):
    if number is None:
        return "info"
    number = float(number)
    # Based in CVSS V2
    if 0 <= number < 4.0:
        return "low"
    elif 4.0 <= number < 7.0:
        return "med"
    elif 7.0 <= number <= 10:
        return "high"


class Ip360Parser:

    def __init__(self, csv_content):
        self.csv_content = StringIO(csv_content.decode('ascii', 'ignore'))
        self.csv_reader = csv.DictReader(self.csv_content, delimiter=',', quotechar='"')

    def parse(self):

        result = []
        for row in self.csv_reader:

            host = {
                "name": row.get("IP"),
                "os": row.get("OS")
            }

            interface = {
                "name": row.get("IP"),
                "hostname_resolution": [row.get("NetBIOS Name")],
                "network_segment": row.get("NetBIOS Domain"),
            }

            service = {"port": row.get("Port")}

            vulnerability = {
                "name": row.get("Vulnerability"),
                "description": row.get("Description"),
                "resolution": row.get("Remediation"),
                "ref": [
                    row.get("CVE"),
                    "Vuln ID: " + row.get("Vulnerability ID"),
                    "Risk: " + row.get("Risk"),
                    "Skill: " + row.get("Skill"),
                    "CVSS V2: " + row.get("CVSS V2"),
                    "CVSS V3: " + row.get("CVSS V3")],
                "severity": row.get("CVSS V2")
            }

            result.append((host, interface, service, vulnerability))

        return result

class Ip360Plugin(PluginBase):
    """
    Example plugin to parse Ip360 output.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Ip360"
        self.name = "Ip360 CSV Output Plugin"
        self.plugin_version = "0.0.1"
        self.options = None

    def parseOutputString(self, output):

        parser = Ip360Parser(output)
        for host, interface, service, vulnerability in parser.parse():
            h_id = self.createAndAddHost(host.get("name"), host.get("os"), hostnames=interface.get("hostname_resolution"))
            if service.get("port") == "-":
                port = "0"
                protocol = "unknown"
            else:
                port = service.get("port").split("/")[0]
                protocol = service.get("port").split("/")[1]

            s_id = self.createAndAddServiceToHost(
                h_id,
                service.get("port"),
                protocol=protocol,
                ports=[port])

            self.createAndAddVulnToService(
                h_id,
                s_id,
                vulnerability.get("name"),
                desc=vulnerability.get("description"),
                resolution=vulnerability.get("resolution"),
                severity=calculate_severity(vulnerability.get("severity")),
                ref=vulnerability.get("ref"))


def createPlugin(ignore_info=False):
    return Ip360Plugin(ignore_info=ignore_info)


