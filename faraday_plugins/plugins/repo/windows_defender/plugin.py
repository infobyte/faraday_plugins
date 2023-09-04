import json
from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Esteban Rodriguez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Esteban Rodriguez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Esteban Rodriguez"
__email__ = "erodriguez@infobytesec.com"
__status__ = "Development"


class WindowsDefenderJsonParser:

    def __init__(self, json_output):
        self.data = json.loads(json_output)

    def parse(self):
        result = []

        for entry in self.data:
            device_name = entry.get('DeviceName')
            os_platform = entry.get('OSPlatform')
            cve_id = entry.get('CveId')
            severity = entry.get('VulnerabilitySeverityLevel')

            # Build the vulnerability description including all fields
            description = f"Device Name: {device_name}\n"
            description += f"OS Platform: {os_platform}\n"
            description += f"CVE ID: {cve_id}\n"
            description += f"Vulnerability Severity Level: {severity}\n"

            result.append({
                "host_info": {
                    "name": "Windows Host",
                    "os": os_platform,
                    "hostname": device_name
                },
                "vulnerability": {
                    "name": cve_id,
                    "severity": severity,
                    "desc": description
                }
            })

        return result

class WindowsDefenderPlugin(PluginJsonFormat):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = "WindowsDefender_Json"
        self.name = "Windows Defender Json"
        self.plugin_version = "1.0"
        self.version = "1.0"
        self.json_keys = {'RbacGroupName'}

    def parseOutputString(self, output):
        parser = WindowsDefenderJsonParser(output)
        parsed_data = parser.parse()

        for entry in parsed_data:
            host_info = entry.get("host_info")
            vulnerability = entry.get("vulnerability")

            host_id = self.createAndAddHost(
                host_info.get("hostname"),
                os=host_info.get("os"),
                hostnames=[host_info.get("hostname")]
            )

            self.createAndAddVulnToHost(host_id,
                name=vulnerability.get("name"),
                severity=vulnerability.get("severity"),
                desc=vulnerability.get("desc")
            )

def createPlugin(*args, **kwargs):
    return WindowsDefenderPlugin(*args, **kwargs)
