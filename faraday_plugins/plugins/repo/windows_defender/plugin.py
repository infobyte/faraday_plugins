""" Create plugin for windows defender"""
import json
from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat


class WindowsDefenderPlugin(PluginMultiLineJsonFormat):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = "WindowsDefender_JSONL"
        self.name = "Windows Defender Jsonl"
        self.plugin_version = "1.0"
        self.version = "1.0"
        self.json_keys = {'LastSeenTimestamp' , 'SecurityUpdateAvailable'}


    def parseOutputString(self, output):
        for json_str in filter(lambda x: x != '', output.split("\n")):
            data = json.loads(json_str)

            device_name = data.pop('DeviceName', 'Unknown')
            if device_name == "Unknown":
                device_name = data.pop('DeviceId', 'Unknown')
            os_platform = data.pop('OSPlatform', 'Unknown')
            cve_id = data.pop('CveId', 'Unknown')
            severity = data.pop('VulnerabilitySeverityLevel', 'Unknown')
            device_id = data.pop('DeviceId', 'Unknown')
            software_name = data.pop('SoftwareName', 'Unknown')
            software_vendor = data.pop('SoftwareVendor', 'Unknown')
            data.pop('CvssScore')

            # Build the vulnerability description including all fields
            # purposely injecte CVE in desc to bypass the cache
            description = f"Device Name: {device_name}\n "\
                          f"Device ID: {device_id}\n "\
                          f"OS Platform: {os_platform}\n" \
                          f"CVE: {cve_id}"
            data_info = "\n".join([f"{key}: {value}" for key, value in data.items()])


            host_id = self.createAndAddHost(
                name=device_name,
                os=os_platform,
                hostnames=[device_name]
            )

            self.createAndAddVulnToHost(
                host_id,
                name= f"{software_name}  {software_vendor} Vulnerable",
                cve=cve_id,
                severity=severity,
                desc=description,
                data=data_info
            )

def createPlugin(*args, **kwargs):
    return WindowsDefenderPlugin(*args, **kwargs)
