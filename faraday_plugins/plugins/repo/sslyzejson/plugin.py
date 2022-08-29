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

    def __init__(self, json_output, resolve_hostname):
        self.resolve_hostname = resolve_hostname
        json_sslyze = json.loads(json_output)
        scan_result = json_sslyze.get('server_scan_results')
        self.list_vul = self.get_vuln(scan_result)

    def get_vuln(self, scan_result):
        list_vuln = []
        if scan_result:
            for scan in scan_result:
                server_info = scan.get('server_info', scan).get('server_location')
                host = self.get_host(server_info) if server_info else {}

                scan_commands_results = scan.get('scan_commands_results', scan.get("scan_result", {}))

                if len(scan_commands_results) > 0:
                    commands = []
                    for command in scan_commands_results:
                        if command.find("cipher") >= 0 and scan_commands_results[command].get('result', True):
                            commands.append(command)
                    ciphers = self.get_cipher(scan_commands_results, commands)
                else:
                    ciphers = {}


                certificate_info = scan_commands_results.get('certificate_info')
                certif = self.get_certification(certificate_info) if certificate_info else {}

                heartbleed_reulsts = scan_commands_results.get('heartbleed')
                heartbleed = self.get_heartbleed(heartbleed_reulsts) if heartbleed_reulsts else {}

                openssl_ccs_injection = scan_commands_results.get('openssl_ccs_injection')
                openssl_ccs = self.get_openssl_ccs(openssl_ccs_injection) if openssl_ccs_injection else {}
                json_vuln = {
                    "host_info": host,
                    "certification": certif,
                    "ciphers": ciphers,
                    "heartbleed": heartbleed,
                    "openssl_ccs": openssl_ccs
                }

                list_vuln.append(json_vuln)
        return list_vuln

    def get_host(self, server_location):
        port = server_location.get('port', None)
        hostname = server_location.get('hostname', None)
        ip = server_location.get('ip_address', self.resolve_hostname(hostname))
        if port != 443:
            url = f"https://{hostname}:{port}"
        else:
            url = f"https://{hostname}"

        json_host = {
            "name": 'https',
            "ip": ip,
            "hostname": hostname,
            "port": port,
            "protocol": 'tcp',
            "url": url
        }

        return json_host

    def get_certification(self, certificate):
        certif_deploy = certificate.get('certificate_deployments', certificate.get('result'))
        certif_deploy = certif_deploy.get('certificate_deployments', [{}]) if isinstance(certif_deploy, dict) else [{}]
        send_certif = certif_deploy[0].get('leaf_certificate_subject_matches_hostname', True)

        if not send_certif:
            subject = certif_deploy[0]['received_certificate_chain'][0]['subject']
            why = subject.get('rfc4514_string')
            if not why:
                why = subject.get('attributes', {}).get('rfc4514_string')
            hostname_used_for_server = certificate.get('hostname_used_for_server_name_indication', certificate.get("result", {})
                                                       .get('hostname_used_for_server_name_indication', 'Not hostname'))
            json_certif = {
                "name": "SSL/TLS Certificate Mismatch",
                "desc": "The software communicates with a host that provides a certificate, but the software does not properly ensure that the certificate is actually associated with that host.",
                "data": f"Certificate {why} does not match server hostname {hostname_used_for_server}",
                "impact": {"integrity": True},
                "ref": ["https://cwe.mitre.org/data/definitions/297.html"],
                "external_id": "CWE-297",
                "severity": "low"
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
        vulnerable_to_heartbleed = heartbleed.get('is_vulnerable_to_heartbleed', heartbleed.get('result', False))
        vulnerable_to_heartbleed = vulnerable_to_heartbleed.get('is_vulnerable_to_heartbleed') if vulnerable_to_heartbleed else False
        if vulnerable_to_heartbleed:
            json_heartbleed = {
                "name": "OpenSSL Heartbleed",
                "desc": "OpenSSL versions 1.0.1 through 1.0.1f contain a flaw in its implementation of the TLS/DTLS heartbeat functionality. This flaw allows an attacker to retrieve private memory of an application that uses the vulnerable OpenSSL library in chunks of 64k at a time. Note that an attacker can repeatedly leverage the vulnerability to retrieve as many 64k chunks of memory as are necessary to retrieve the intended secrets. The sensitive information that may be retrieved using this vulnerability include:\n\n Primary key material (secret keys)\n Secondary key material (user names and passwords used by vulnerable services)\n Protected content (sensitive data used by vulnerable services)\n Collateral (memory addresses and content that can be leveraged to bypass exploit mitigations)\n Exploit code is publicly available for this vulnerability.  Additional details may be found in CERT/CC Vulnerability Note VU#720951.",
                "impact": {"confidentiality": True},
                "ref": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160", "https://heartbleed.com/", "https://us-cert.cisa.gov/ncas/alerts/TA14-098A"],
                "external_id": "CVE-2014-0160",
                "severity": "high"
            }
        return json_heartbleed

    def get_openssl_ccs(self, openssl_ccs):
        json_openssl_ccs = {}
        is_vulnerable_to_ccs_injection = openssl_ccs.get('is_vulnerable_to_ccs_injection', openssl_ccs.get('result', False))
        is_vulnerable_to_ccs_injection = is_vulnerable_to_ccs_injection.get('is_vulnerable_to_ccs_injection', False) if is_vulnerable_to_ccs_injection else False
        if is_vulnerable_to_ccs_injection:
            json_openssl_ccs = {
                "name": "OpenSSL CCS Injection",
                "desc": 'OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the "CCS Injection" vulnerability."',
                "impact": {"confidentiality": True, "integrity": True},
                "ref": ["http://ccsinjection.lepidum.co.jp/", "https://nvd.nist.gov/vuln/detail/CVE-2014-0224"],
                "external_id": "CVE-2014-0224",
                "severity": "high"
            }
        return json_openssl_ccs


class SslyzePlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Sslyze_JSON"
        self.name = "Sslyze Json"
        self.plugin_version = "0.1"
        self.version = "3.4.5"
        self.json_keys = {'server_scan_results', 'sslyze_url', 'sslyze_version'}
        self._command_regex = re.compile(r'^(sudo sslyze|sslyze|\.\/sslyze)\s+.*?')
        self.json_arg_re = re.compile(r"^.*(--json_out\s*[^\s]+).*$")
        self._use_temp_file = True
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        parser = SslyzeJsonParser(output, self.resolve_hostname)

        for info_sslyze in parser.list_vul:
            info_sslyze['host_info'].get('hostname')
            host_id = self.createAndAddHost(
                info_sslyze['host_info'].get('ip'),
                os="unknown",
                hostnames=[
                    info_sslyze['host_info'].get('hostname')
                ]
            )
            service_id = self.createAndAddServiceToHost(
                host_id,
                name=info_sslyze['host_info'].get('name'),
                protocol=info_sslyze['host_info'].get('protocol'),
                ports=[
                    info_sslyze['host_info'].get('port')
                ]
            )

            if info_sslyze['certification']:
                self.createAndAddVulnWebToService(
                    host_id,
                    service_id,
                    name=info_sslyze['certification'].get('name'),
                    desc=info_sslyze['certification'].get('desc'),
                    data=info_sslyze['certification'].get('data'),
                    impact=info_sslyze['certification'].get('impact'),
                    ref=info_sslyze['certification'].get('ref'),
                    easeofresolution="trivial",
                    external_id=info_sslyze['certification'].get('external_id'),
                    website=info_sslyze['host_info'].get('url'),
                    severity=info_sslyze['certification'].get('severity'))

            cipherlist = []
            if info_sslyze['ciphers']:
                for k, v in info_sslyze['ciphers'].items():
                    if len(v) != 0:
                        for ciphers in v:
                            key = k.replace('_cipher_suites', '')
                            cipherlist.append(f"In protocol [{key}], weak cipher suite: {ciphers}")
                if cipherlist:
                    self.createAndAddVulnWebToService(
                        host_id,
                        service_id,
                        name="SSL/TLS Weak Cipher Suites Supported",
                        desc="The software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.",
                        data="\n".join(cipherlist),
                        impact={"confidentiality": True},
                        ref=["https://cwe.mitre.org/data/definitions/326.html"],
                        easeofresolution="trivial",
                        external_id="CWE-326",
                        website=info_sslyze['host_info'].get('url'),
                        severity="low")

            if info_sslyze['heartbleed']:
                self.createAndAddVulnWebToService(
                    host_id,
                    service_id,
                    name=info_sslyze['heartbleed'].get('name'),
                    desc=info_sslyze['heartbleed'].get('desc'),
                    impact=info_sslyze['heartbleed'].get('impact'),
                    ref=info_sslyze['heartbleed'].get('ref'),
                    easeofresolution="trivial",
                    external_id=info_sslyze['heartbleed'].get('external_id'),
                    website=info_sslyze['host_info'].get('url'),
                    severity=info_sslyze['heartbleed'].get('severity'))

            if info_sslyze['openssl_ccs']:
                self.createAndAddVulnWebToService(
                    host_id,
                    service_id,
                    name=info_sslyze['openssl_ccs'].get('name'),
                    desc=info_sslyze['openssl_ccs'].get('desc'),
                    impact=info_sslyze['openssl_ccs'].get('impact'),
                    ref=info_sslyze['openssl_ccs'].get('ref'),
                    easeofresolution="trivial",
                    external_id=info_sslyze['openssl_ccs'].get('external_id'),
                    website=info_sslyze['host_info'].get('url'),
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


def createPlugin(*args, **kwargs):
    return SslyzePlugin(*args, **kwargs)
