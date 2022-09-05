"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
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


class SslLabsJsonParser:

    def __init__(self, json_output):
        list_data = json.loads(json_output)
        self.json_data = list_data[0]

    def host_info(self, data):
        host_information = {
            "url": data.get('host', 'Not Info'),
            "description_host": "SSL Labs",
            "port": data.get('port', 0),
            "protocol": data.get('protocol', 'Not Info'),
            "status": data.get('status', 'Not Info'),
            "version": data.get('engineVersion', '0.0.0'),
            "run_date": data.get('startTime', 'Not Info')
        }
        return host_information

    def get_ip(self, data):
        for ip in data:
            return ip.get('ipAddress', '0.0.0.0')

    def get_vulns(self, data):
        chain = data.get('chain', None)
        vuln_list = []
        policies_list = [data.get('hstsPolicy', 'No Information'),
                         data.get('hpkpPolicy', 'No Information'),
                         data.get('hpkpRoPolicy', 'No Information')]

        for vulns in chain['certs']:
            vuln = {
                "name": vulns.get('issuerLabel', 'No Information'),
                "desc": vulns.get('issuerSubject', 'No Information'),
                "data": f'SHA1HASH: {vulns.get("sha1Hash", "No Information")}'
                        f'PINSHA256: {vulns.get("pinSha256", "No Information")}'
                        f'RAW: {vulns.get("raw", "No Information")}',
                "policy": policies_list
            }
            vuln_list.append(vuln)
        return vuln_list


class SslLabsPlugin(PluginJsonFormat):
    """ Handle the SSL Labs tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "ssllabs"
        self.name = "SSL Labs"
        self.plugin_version = "0.1"
        self.version = "3.4.5"
        self.json_keys = {'engineVersion', 'criteriaVersion', 'endpoints'}


    def parseOutputString(self, output):
        parser = SslLabsJsonParser(output)
        host = parser.host_info(parser.json_data)

        host_id = self.createAndAddHost(
            name=parser.get_ip(parser.json_data['endpoints']),
            hostnames=[host['url']],
            description=host['description_host'])

        service_id = self.createAndAddServiceToHost(
            host_id=host_id,
            name=host['url'],
            protocol=host['protocol'],
            ports=host['port'],
            status=host['status'],
            version=host['version'])

        vulns = parser.get_vulns(parser.json_data['endpoints'][0]['details'])

        for vuln in vulns:
            policy_info = f"Long max age: {vuln['policy'][0]['LONG_MAX_AGE']}" \
                          f"Status: {vuln['policy'][0]['status']} | {vuln['policy'][1]['status']} | {vuln['policy'][2]['status']} " \
                          f"directives: {vuln['policy'][0]['directives']} | {vuln['policy'][1]['directives']} | {vuln['policy'][2]['directives']}" \
                          f"pins: {vuln['policy'][1]['directives']} | {vuln['policy'][2]['directives']} " \
                          f"matchedPins: {vuln['policy'][1]['matchedPins']} | {vuln['policy'][2]['matchedPins']} "

            self.createAndAddVulnToService(host_id,
                                           service_id=service_id,
                                           name=vuln['name'],
                                           desc=vuln['desc'],
                                           policyviolations=[policy_info],
                                           data=vuln['data'])


def createPlugin(*args, **kwargs):
    return SslLabsPlugin(*args, **kwargs)
