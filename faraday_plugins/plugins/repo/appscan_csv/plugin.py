"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""

from faraday_plugins.plugins.plugin import PluginCSVFormat
from itertools import islice
import csv
from dateutil.parser import parse

__author__ = "Erodriguez"
__copyright__ = "Copyright (c) 2019, Infobyte LLC"
__credits__ = ["Erodriguez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Erodriguez"
__email__ = "erodriguez@infobytesec.com"
__status__ = "Development"


class Appscan_CSV_Plugin(PluginCSVFormat):
    """
    Example plugin to parse Appscan output.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.csv_headers = {'HCL AppScan on Cloud'}
        self.id = "Appscan_CSV"
        self.name = "Appscan CSV Output Plugin"
        self.plugin_version = "0.0.1"
        self.version = "0.0.1"
        self.framework_version = "1.0.1"

    def _parse_filename(self, filename):
        with open(filename) as output:
            self.parseOutputString(islice(output, 15, None))

    def parseOutputString(self, output):
        try:
            reader = csv.DictReader(output)
        except:
            print("Error parser output")
            return None

        for row in reader:
            #Skip Fix Group
            if row["Issue Id"] == "Fix Group Attributes:":
                break
            path = row['Source File']
            if path == "":
                path = row['Location']
            try:
                run_date = parse(row['Date Created'])
            except:
                run_date = None
            name = row["Issue Type Name"]
            references = []
            if row["Cwe"]:
                references.append(f"CWE-{row['Cwe']}")
            if row["Cve"]:
                references.append(row["Cve"])

            data = []
            if row['Security Risk']:
                data.append(f"Security Risk: {row['Security Risk']}")
            desc = [row['Description']]
            if row['Cve']:
                desc.append(f"Cve:  {row['Cve']}")
            if row['Line']:
                desc.append(f"Line:  {row['Line']}")
            if row['Cause']:
                desc.append(f"Cause:  {row['Cause']}")
            if row['Remediation']:
                desc.append(f"Resolution:  {row['Resolution']}")
            if row['Threat Class']:
                desc.append(f"Threat Class:   {row['Threat Class']}")
            if row['Security Risk']:
                desc.append(f"Security Risk:   {row['Security Risk']}")
            if row['Calling Method']:
                desc.append(f"Calling Method:   {row['Calling Method']}")
            if row['Location']:
                desc.append(f"Vulnerability Line:   {row['Location']}")

            h_id = self.createAndAddHost(name=path)
            self.createAndAddVulnToHost(
                h_id,
                name=name,
                desc=" \n".join(desc),
                resolution=row['Remediation'],
                external_id=row['Issue Id'],
                cve=row['Cve'],
                run_date=run_date,
                severity=row["Severity"],
                ref=references,
                data=" \n".join(data)
            )

def createPlugin(*args, **kargs):
    return Appscan_CSV_Plugin(*args, **kargs)
