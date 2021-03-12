"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import socket
import json
from datetime import datetime
import re
from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat

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


class AwsProwlerPlugin(PluginMultiLineJsonFormat):
    """ Handle the AWS Prowler tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "awsprowler"
        self.name = "AWS Prowler"
        self.plugin_version = "0.1"
        self.version = "0.0.1"
        self.json_keys = {"Profile", "Account Number"}


    def parseOutputString(self, output, debug=False):
        parser = AwsProwlerJsonParser(output)
        region_list = []
        for region in parser.report_aws:
            json_reg = json.loads(region)
            region_list.append(json_reg.get('Region', 'Not Info'))

        host_id = self.createAndAddHost(name=f'{self.name} - {region_list}', description="AWS Prowler")

        for vuln in parser.report_aws:
            json_vuln = json.loads(vuln)
            vuln_name = json_vuln.get('Control', 'Not Info')
            vuln_desc = json_vuln.get('Message', 'Not Info')
            vuln_severity = json_vuln.get('Level', 'Not Info')
            vuln_run_date = json_vuln.get('Timestamp', 'Not Info')
            vuln_external_id = json_vuln.get('Control ID', 'Not Info')
            vuln_policy = f'{vuln_name}:{vuln_external_id}'
            vuln_run_date = vuln_run_date.replace('T', ' ')
            vuln_run_date = vuln_run_date.replace('Z', '')
            self.createAndAddVulnToHost(host_id=host_id, name=vuln_name, desc=vuln_desc,
                                        severity=self.normalize_severity(vuln_severity),
                                        run_date=datetime.strptime(vuln_run_date, '%Y-%m-%d %H:%M:%S'),
                                        external_id=vuln_external_id, policyviolations=[vuln_policy])


def createPlugin(ignore_info=False):
    return AwsProwlerPlugin(ignore_info=ignore_info)
