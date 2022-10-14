"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""

from faraday_plugins.plugins.plugin import PluginCSVFormat
import csv
import io


__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2019, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"


class NessusScPlugin(PluginCSVFormat):
    """
    Example plugin to parse Nessus Sc output.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.csv_headers = [{'Plugin', 'Plugin Name'}]
        self.id = "Nessus_sc"
        self.name = "Nessus Sc Output Plugin"
        self.plugin_version = "1.0.0"
        self.version = "1.0.0"
        self.framework_version = "1.0.0"

    def parseOutputString(self, output):
        try:
            reader = csv.DictReader(io.StringIO(output))
        except:
            print("Error parser output")
            return None

        for row in reader:
            ip = row['IP Address']
            hostname = row['DNS Name']
            h_id = self.createAndAddHost(name=ip, hostnames=hostname)
            protocol = row['Protocol']
            port = row['Port']
            s_id = self.createAndAddServiceToHost(h_id, name=port, protocol=protocol, ports=port, status="open")
            name = row['Plugin Name']
            severity = row['Severity']
            description = row['Description']
            vuln = {"name": name, "severity": severity, "desc": description}
            solution = row['Solution']
            if solution:
                vuln["resolution"] = solution
            cvss3_vector = row['CVSS V3 Vector']
            if cvss3_vector:
                if not cvss3_vector.startswith("CVSS:3.0/"):
                    cvss3_vector = "CVSS:3.0/"+cvss3_vector
                vuln["cvss3"] = {"vector_string": cvss3_vector}
            cvss2_vector = row['CVSS V2 Vector']
            if cvss2_vector:
                vuln["cvss2"] = {"vector_string": cvss2_vector}
            external_ref = row["See Also"]
            cross_ref = row["Cross References"]
            references = []
            if external_ref:
                references.append(external_ref)
            if cross_ref:
                references.append(cross_ref)
            vuln["ref"] = references
            cve = row['CVE']
            if cve:
                vuln["cve"] = cve
            self.createAndAddVulnToService(h_id, s_id, **vuln)


def createPlugin(*args, **kwargs):
    return NessusScPlugin(*args, **kwargs)
