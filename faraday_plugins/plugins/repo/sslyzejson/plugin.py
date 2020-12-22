"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re
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


class SslyzeJsonParser:

    def __init__(self, json_output):
        json_sslyze = json.loads(json_output)
        scan_result = json_sslyze.get('server_scan_results')
        self.list_vul = self.get_vuln(scan_result)

    def get_vuln(self, scan_result):
        list_vuln = []
        if scan_result:
            for scan in scan_result:
                try:
                    host = self.get_host(scan['server_info']['server_location'])
                except KeyError:
                    host = {}

                try:
                    certif = self.get_certification(scan['scan_commands_results']['certificate_info'])
                except KeyError:
                    certif = {}

                if not scan['scan_commands']:
                    ciphers = {}
                else:
                    commands = []
                    for command in scan['scan_commands']:
                        if command.find("cipher") >= 0:
                            commands.append(command)
                    ciphers = self.get_cipher(scan['scan_commands_results'], commands)

                try:
                    heartbleed = self.get_heartbleed(scan['scan_commands_results']['heartbleed'])
                except KeyError:
                    heartbleed = {}

                try:
                    openssl_ccs = self.get_openssl_ccs(scan['scan_commands_results']['openssl_ccs_injection'])
                except KeyError:
                    openssl_ccs = {}

                json_vuln = {
                    "host_info": host,
                    "certification": certif,
                    "ciphers": ciphers,
                    "heartbleed": heartbleed,
                    "openssl_ccs":openssl_ccs
                }

                list_vuln.append(json_vuln)
        return list_vuln

    def get_host(self, server_location):
        port = server_location.get('port', None)
        protocol = ''
        if port is not None:
            if port == 443:
                protocol = 'https'
            else:
                protocol = 'http'

        json_host = {
            "url": server_location.get('hostname', None),
            "ip": server_location.get('ip_address', '0.0.0.0'),
            "port": port,
            "protocol": protocol
        }

        return json_host

    def get_certification(self, certificate):
        certif_deploy = certificate['certificate_deployments']
        send_certif = certif_deploy[0].get('leaf_certificate_subject_matches_hostname', True)

        if not send_certif:
            json_certif = {
                "name": "Certificate mismatch",
                "desc": f"Certificate does not match server hostname {certificate.get('hostname_used_for_server_name_indication', 'Not hostname')}",
                "severity": "info"
            }
        else:
            json_certif = {}
        return json_certif

    def get_cipher(self, scan_result, list_commands):
        weak_cipher_list = [
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
            "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
        ]
        weak_cipher = {}
        for command in list_commands:
            weak_cipher[command] = []
            try:
                if scan_result[command]['accepted_cipher_suites']:
                    for cipher_suite in scan_result[command]['accepted_cipher_suites']:
                        name_cipher = cipher_suite['cipher_suite'].get('name')
                        if name_cipher in weak_cipher_list:
                            if name_cipher not in weak_cipher[command]:
                                weak_cipher[command].append(name_cipher)
            except KeyError:
                pass

            try:
                if scan_result[command]['cipher_suite_preferred_by_server'] is not None:
                    for cipher_suite in scan_result[command]['accepted_cipher_suites']:
                        name_cipher = cipher_suite['cipher_suite'].get('name')
                        if name_cipher in weak_cipher_list:
                            if name_cipher not in weak_cipher[command]:
                                weak_cipher[command].append(name_cipher)
            except KeyError:
                pass

        return weak_cipher

    def get_heartbleed(self, heartbleed):
        json_heartbleed = {}
        if heartbleed.get('is_vulnerable_to_heartbleed', False):
            json_heartbleed = {
                "name": "OpenSSL Heartbleed",
                "desc": "OpenSSL Heartbleed is vulnerable",
                "severity": "critical"
            }
        return json_heartbleed

    def get_openssl_ccs(self, openssl_ccs):
        json_openssl_ccs = {}
        if openssl_ccs.get('is_vulnerable_to_ccs_injection', False):
            json_openssl_ccs = {
                "name": "OpenSSL CCS Injection",
                "desc": "OpenSSL CCS Injection is vulnerable",
                "severity": "medium"
            }
        return json_openssl_ccs


class SslyzePlugin(PluginJsonFormat):

    def __init__(self):
        super().__init__()
        self.id = "Sslyze JSON"
        self.name = "Sslyze Json"
        self.plugin_version = "0.1"
        self.version = "3.4.5"
        self.json_keys = {'server_scan_results', 'sslyze_url'}
        self._command_regex = re.compile(r'^(sudo sslyze|sslyze|\.\/sslyze)\s+.*?')
        self.json_arg_re = re.compile(r"^.*(--json_out\s*[^\s]+).*$")

    def parseOutputString(self, output):
        parser = SslyzeJsonParser(output)

        for info_sslyze in parser.list_vul:
            info_sslyze['host_info'].get('url')
            host_id = self.createAndAddHost(
                info_sslyze['host_info'].get('ip'),
                os="unknown",
                hostnames=[
                    info_sslyze['host_info'].get('url')
                ]
            )
            service_id = self.createAndAddServiceToHost(
                host_id,
                name=info_sslyze['host_info'].get('protocol'),
                protocol=info_sslyze['host_info'].get('protocol'),
                ports=[
                    info_sslyze['host_info'].get('port')
                ]
            )

            if info_sslyze['certification']:
                self.createAndAddVulnToService(
                    host_id,
                    service_id,
                    name=info_sslyze['certification'].get('name'),
                    desc=info_sslyze['certification'].get('desc'),
                    severity=info_sslyze['certification'].get('info'))

            if info_sslyze['ciphers']:
                for k, v in info_sslyze['ciphers'].items():
                    if len(v) != 0:
                        for ciphers in v:
                            key = k.replace('_cipher_suites', '')
                            self.createAndAddVulnToService(
                                host_id,
                                service_id,
                                name=ciphers,
                                desc=f"In protocol [{key}], weak cipher suite: {ciphers}",
                                severity="low")

            if info_sslyze['heartbleed']:
                self.createAndAddVulnToService(
                    host_id,
                    service_id,
                    name=info_sslyze['heartbleed'].get('name'),
                    desc=info_sslyze['heartbleed'].get('desc'),
                    severity=info_sslyze['heartbleed'].get('severity'))

            if info_sslyze['openssl_ccs']:
                self.createAndAddVulnToService(
                    host_id,
                    service_id,
                    name=info_sslyze['openssl_ccs'].get('name'),
                    desc=info_sslyze['openssl_ccs'].get('desc'),
                    severity=info_sslyze['openssl_ccs'].get('severity'))

    def processCommandString(self, username, current_path, command_string):
        super().processCommandString(username, current_path, command_string)
        arg_match = self.json_arg_re.match(command_string)
        if arg_match is None:
            return re.sub(r"(^.*?sslyze)",
                          r"\1 --json_out %s" % self._output_file_path,
                          command_string)
        else:
            return re.sub(arg_match.group(1),
                          r"--json_out %s" % self._output_file_path,
                          command_string)


def createPlugin():
    return SslyzePlugin()

