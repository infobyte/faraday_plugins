"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import socket
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat


__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class AwsProwlerJsonParser:

    def __init__(self, json_output):
        string_manipulate = json_output.replace("}", "} #")
        string_manipulate = string_manipulate[:len(string_manipulate) - 2]
        self.report_aws = string_manipulate.split("#")


class AwsProwlerPlugin(PluginJsonFormat):
    """ Handle the AWS Prowler tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self):
        super().__init__()
        self.id = "awsprowler"
        self.name = "AWS Prowler"
        self.plugin_version = "0.1"
        self.version = "0.0.1"
        self.json_keys = {""}

    def parseOutputString(self, output, debug=False):
        parser = AwsProwlerJsonParser(output)
        host_id = self.createAndAddHost(name='0.0.0.0', description="AWS Prowler")
        for vuln in parser.report_aws:
            json_vuln = json.loads(vuln)
            vuln_name = json_vuln.get('Account Number', 'Not Info')
            vuln_desc = json_vuln.get('Control', 'Not Info')
            vuln_severity = json_vuln.get('Level', 'Not Info')
            vuln_run_date = json_vuln.get('Timestamp', 'Not Info')
            vuln_status = json_vuln.get('Status', 'Not Info')
            vuln_external_id = json_vuln.get('Control ID', 'Not Info')
            vuln_data = json_vuln.get('Message', 'Not Info')

            self.createAndAddVulnToHost(host_id=host_id, name=vuln_name, desc=vuln_desc,
                                        severity=self.normalize_severity(vuln_severity),
                                        run_date=vuln_run_date, status=vuln_status,
                                        external_id=vuln_external_id, data=vuln_data)


def createPlugin():
    return AwsProwlerPlugin()
