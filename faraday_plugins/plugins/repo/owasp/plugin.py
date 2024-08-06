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
            cvss3_base = row.get('CVSSv3_BaseScore')
            cvss2_score = row.get('CVSSv2_Score')
            vulnerability_name = row.get('Vulnerability')

            # Create host
            host_id = self.createAndAddHost(name=ip)

            # Create vulnerability
            self.createAndAddVulnToHost(host_id,
                                        name=vulnerability_name,
                                        desc=description,
                                        severity=severity_map.get(severity, 'info'),
                                        cve=cve,
                                        cwe=cwe,
                                        cvss3={"base_score": cvss3_base},
                                        cvss2={"base_score": cvss2_score},
                                        )


def createPlugin(*args, **kwargs):
    return owaspDependencyCheckPlugin(*args, **kwargs)
