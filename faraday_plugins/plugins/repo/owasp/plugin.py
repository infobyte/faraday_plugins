import csv
import io
import re
from collections import defaultdict
from copy import copy
"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""

from faraday_plugins.plugins.plugin import PluginCSVFormat


severity_map = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MEDIUM': 'medium',
    'LOW': 'low'
}


class owaspDependencyCheckPlugin(PluginCSVFormat):
    """
    Parses OWASP Dependency Check reports in CSV format.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "owaspDependencyCheck"
        self.name = "OWASP Dependency Check Plugin"
        self.plugin_version = "1.0.0"
        self.version = "1.0.0"
        self.framework_version = "1.0.0"
        self.csv_headers = {"Project", "ScanDate", "DependencyName", "DependencyPath", "Description"}

    def parseOutputString(self, output):
        try:
            reader = csv.DictReader(io.StringIO(output))
        except Exception as e:
            print(f"Error parsing output: {e}")
            return None

        for row in reader:
            ip = row.get("Project")
            description = row.get("Description")
            dep_name = row.get('DependencyName')
            dep_path = row.get('DependencyPath')
            cve = row.get('CVE')
            cwe = row.get('CWE')
            severity = row.get('CVSSv3_BaseSeverity')
            cvss3 = row.get('CVSSv3')
            cvss2 = row.get('CVSSv2')
            vulnerability_name = row.get('Vulnerability')

            # Create host
            host_id = self.createAndAddHost(name=ip)

            # Create vulnerability
            self.createAndAddVulnToHost(host_id,
                                        name=vulnerability_name,
                                        desc=f"{description}\nDependencyName: {dep_name}\nDependencyPath: {dep_path}",
                                        severity=severity_map.get(severity, 'info'),
                                        cve=cve,
                                        cwe=cwe,
                                        cvss3={"vector_string": cvss3},
                                        cvss2={"vector_string": cvss2},
                                        )


def createPlugin(*args, **kwargs):
    return owaspDependencyCheckPlugin(*args, **kwargs)
