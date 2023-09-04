import json
from faraday_plugins.plugins.plugin import PluginJsonFormat

class WindowsDefenderPlugin(PluginJsonFormat):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = "WindowsDefender_JSON"
        self.name = "Windows Defender Json"
        self.plugin_version = "1.0"
        self.version = "1.0"
        self.json_keys = {'LastSeenTimestamp' , 'SecurityUpdateAvailable'}  # Define the relevant JSON keys here
        self._command_regex = None
        self.json_arg_re = None
        self._use_temp_file = False
        self._temp_file_extension = None

    def parseOutputString(self, output):
        try:
            data_list = output.strip().split('\n')  # Split the input into lines

            for json_str in data_list:
                data = json.loads(json_str, object_hook=dict)  # Force conversion to a dictionary

                device_name = data.get('DeviceName', 'Unknown')
                os_platform = data.get('OSPlatform', 'Unknown')
                cve_id = data.get('CveId', 'Unknown')
                severity = data.get('VulnerabilitySeverityLevel', 'Unknown')
                DeviceId = data.get('DeviceId', 'Unknown')
                SoftwareName = data.get('SoftwareName', 'Unknown')
                SoftwareVendor = data.get('SoftwareVendor', 'Unknown')

                key_value_pairs = "\n".join([f"{key}: {value}\n" for key, value in data.items()])


                # Build the vulnerability description including all fields
                description = f"Device Name: {device_name}\n "
                description += f"OS Platform: {os_platform}\n "
                description += f"CVE ID: {cve_id}\n "
                description += f"Vulnerability Severity Level: {severity}\n "
                description += f"Device ID: {severity}\n "
                description += f"Device ID: {key_value_pairs}\n "


                host_id = self.createAndAddHost(
                    name=device_name,
                    os=os_platform,
                    hostnames=[device_name]
                )

                self.createAndAddVulnToHost(
                    host_id,
                    name= f"{SoftwareName}  {SoftwareVendor} Vulnerable",
                    cve=cve_id,
                    severity=severity,
                    desc=description
                )

        except json.JSONDecodeError as e:
            self.logger.error(f"Error decoding JSON data: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error parsing JSON data: {str(e)}")

def createPlugin(*args, **kwargs):
    return WindowsDefenderPlugin(*args, **kwargs)