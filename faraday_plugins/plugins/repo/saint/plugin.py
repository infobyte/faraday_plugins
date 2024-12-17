"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""

from faraday_plugins.plugins.plugin import PluginCSVFormat
from faraday_plugins.plugins.plugins_utils import get_severity_from_cvss
import csv
import io


__author__ = "Dante Acosta"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Dante Acosta"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Dante Acosta"
__email__ = "dacosta@infobytesec.com"
__status__ = "Development"


class SaintPlugin(PluginCSVFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "saint"
        self.name = "Saint"
        self.plugin_version = "1.0.0"
        self.version = "1.0.0"
        self.framework_version = "1.0.0"
        self.csv_headers = {'IP Address', 'Hostname', 'System Type', 'Severity Level', 'Severity'}

    def parseOutputString(self, output):
        try:
            reader = csv.DictReader(io.StringIO(output))
        except Exception as e:
            print(f"Error parsing output {e}")
            return None

        for row in reader:
            host_id = self.createAndAddHost(
                name=row.get("IP Address", ""),
                os=row.get("System Class") or "unknown",
                hostnames=[row.get("Hostname")] or []
            )
            self.createAndAddVulnToHost(
                host_id,
                name=row.get("Tutorial"),
                desc=row.get("Description"),
                severity=get_severity_from_cvss(row.get("CVSS Score", "")),
                confirmed=True if row.get("Confirmed", "").lower() == "yes" else False
            )


def createPlugin(*args, **kwargs):
    return SaintPlugin(*args, **kwargs)
