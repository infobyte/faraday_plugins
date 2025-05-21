"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from faraday_plugins.plugins.plugin import PluginCSVFormat
import pandas as pd
from io import StringIO

__author__ = "Erodriguez"
__copyright__ = "Copyright (c) 2019, Infobyte LLC"
__credits__ = ["Erodriguez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Erodriguez"
__email__ = "erodriguez@faradaysec.com"
__status__ = "Development"


class SecScoreCard_CSV(PluginCSVFormat):
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
            # Read CSV into a DataFrame
            df = pd.read_csv(StringIO(output))

            # Iterate through DataFrame rows
            for _, row in df.iterrows():
                # Get path from different possible columns
                path = (
                    row.get("FINAL URL", "")
                    or row.get("IP ADDRESS", "")
                    or row.get("HOSTNAME", "")
                )

                name = row.get("ISSUE TYPE TITLE", "")

                # Handle references
                references = []
                if pd.notna(row.get("CVE")):
                    references.append(row["CVE"])

                # Handle description
                desc = str(row.get("DESCRIPTION", ""))

                # Create host and vulnerability
                h_id = self.createAndAddHost(name=path)
                self.createAndAddVulnToHost(
                    h_id,
                    name=name,
                    desc=desc,
                    resolution=str(row.get("ISSUE RECOMMENDATION", "")),
                    external_id=str(row.get("ISSUE ID", "")),
                    cve=str(row.get("CVE", "")),
                    severity=str(row.get("ISSUE TYPE SEVERITY", "")),
                    ref=references,
                    data=str(row.get("DATA", "")),
                )

        except Exception as e:
            print(f"Error parsing output: {str(e)}")
            return None


def createPlugin(*args, **kargs):
    return SecScoreCard_CSV(*args, **kargs)
