"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat


__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2019, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class SourceclearJsonParser:
    def __init__(self, json_output):
        self.json_data = json.loads(json_output)


class SourceclearPlugin(PluginJsonFormat):
    """ Handle the Sourceclear tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self):
        super().__init__()
        self.id = "sourceclear"
        self.name = "Sourceclear"
        self.plugin_version = "0.1"
        self.version = "0.0.1"
        self.json_keys = {"metadata", "records"}

    def parseOutputString(self, output, debug=False):
        parser = SourceclearJsonParser(output)
        vulns = {}
        for records in parser.json_data['records']:
            vulns = records['vulnerabilities']
            h_id = self.createAndAddHost(name='0.0.0.0', scan_template=records['metadata']['recordType'])
            s_id = self.createAndAddServiceToHost(h_id, "Sourceclear", status='open')

        for vuln in vulns:
            v_name = vuln['title']
            v_desc = vuln['overview']
            v_ref = "CVSS: {}".format(vuln['cvssScore'])
            #v_type = vuln['vulnerabilityTypes']
            v_data = vuln['libraries']
            v_website = vuln['_links']
            self.createAndAddVulnWebToService(h_id, s_id, name=v_name, desc=v_desc, ref=[v_ref], data=v_data,
                                              website=v_website)


def createPlugin():
    return SourceclearPlugin()
