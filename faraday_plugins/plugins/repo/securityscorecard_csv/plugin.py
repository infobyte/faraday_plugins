"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import sys
import io
from faraday_plugins.plugins.plugin import PluginCSVFormat
import csv


__author__ = "Erodriguez"
__copyright__ = "Copyright (c) 2019, Infobyte LLC"
__credits__ = ["Erodriguez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Erodriguez"
__email__ = "erodriguez@faradaysec.com"
__status__ = "Development"


class SecScoreCard(PluginCSVFormat):
    """
    Example plugin to parse SecScoreBoard_CSV output.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.csv_headers = [{"LABEL"}, {"PROVIDER"}]
        self.id = "SecScoreCard_CSV"
        self.name = "SecScoreCard_CSV Output Plugin"
        self.plugin_version = "0.0.1"
        self.version = "0.0.1"
        self.framework_version = "1.0.1"

    def parseOutputString(self, output):
        try:
            csv.field_size_limit(sys.maxsize)
            print(str(output))
            csv_file = io.StringIO(output)
            reader = csv.DictReader(csv_file, delimiter=",")
            for row in reader:
                path = row.get("FINAL URL", "")
                if not path:
                    path = row.get("IP ADDRESS", "")
                if not path:
                    path = row.get("HOSTNAME", "")
                if not path:
                    continue

                # Skip if HOSTNAME is empty or not a valid IP
                hostname = row.get("HOSTNAME", "")

                name = row.get("ISSUE TYPE TITLE", "")

                # Handle references
                references = []
                cve = row.get("CVE", "")
                if cve:
                    references.append(cve)

                # Handle description
                desc = row.get("DESCRIPTION", "")

                # Create host and vulnerability
                h_id = self.createAndAddHost(
                    name=path,
                    hostnames=hostname,
                )
                self.createAndAddVulnToHost(
                    host_id=h_id,
                    name=name,
                    desc=desc,
                    resolution=str(row.get("ISSUE RECOMMENDATION", "")),
                    external_id=str(row.get("ISSUE ID", "")),
                    cve=str(cve),
                    severity=str(row.get("ISSUE TYPE SEVERITY", "")),
                    ref=references,
                    data=str(row.get("DATA", "")),
                )

        except Exception as e:
            print(f"Error parsing output: {str(e)}")
            return None


def createPlugin(*args, **kargs):
    return SecScoreCard(*args, **kargs)
