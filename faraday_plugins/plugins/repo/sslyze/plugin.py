import re
from faraday_plugins.plugins.plugin import PluginXMLFormat

try:
    from lxml import etree as ET
except ImportError:
    import xml.etree.ElementTree as ET

WEAK_CIPHER_LIST = [
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


class SslyzeXmlParser:

    def __init__(self, xml_output):
        self.parser = self.parse_xml(xml_output)
        self.target = self.get_target(self.parser)
        self.certificate = self.get_hostname_validation(self.parser)
        self.cipher_suite = self.get_weak_cipher_suite(self.parser)
        self.heart_bleed = self.get_heartbleed(self.parser)
        self.open_ssl_ccs = self.get_openssl_ccs(self.parser)

    def parse_xml(self, xml_output):
        try:
            tree = ET.fromstring(xml_output)
            return tree
        except IndexError:
            print("Syntax error")
            return None

    def get_target(self, tree):
        return tree.xpath('//target')

    def get_hostname_validation(self, tree):
        return tree.xpath('//hostnameValidation')

    def get_protocol_name(self, tree):
        protocol_supported = []
        protocols = []
        protocols.append(tree.xpath('//sslv2'))
        protocols.append(tree.xpath('//sslv3'))
        protocols.append(tree.xpath('//tlsv1'))
        protocols.append(tree.xpath('//tlsv1_1'))
        protocols.append(tree.xpath('//tlsv1_2'))
        protocols.append(tree.xpath('//tlsv1_3'))

        for protocol in protocols:
            if protocol[0].attrib['isProtocolSupported'] == "True":
                protocol_supported.append(protocol[0])

        return protocol_supported

    def get_weak_cipher_suite(self, tree):
        protocols = self.get_protocol_name(tree)
        weak_cipher = {}

        for protocol in protocols:
            weak_cipher[protocol.tag] = []
            for ciphers in protocol:
                if ciphers.tag == 'preferredCipherSuite' or ciphers.tag == 'acceptedCipherSuites':
                    for cipher in ciphers:
                        if cipher.attrib['name'] in WEAK_CIPHER_LIST:
                            if not cipher.attrib['name'] in weak_cipher[protocol.tag]:
                                weak_cipher[protocol.tag].append(cipher.attrib['name'])

        return weak_cipher

    def get_heartbleed(self, tree):
        return tree.xpath('//heartbleed')

    def get_openssl_ccs(self, tree):
        return tree.xpath('//openssl_ccs')


class SslyzePlugin(PluginXMLFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "document"
        self.id = "Sslyze_XML"
        self.name = "Sslyze Plugin"
        self.plugin_version = "0.0.1"
        self.version = "2.0.6"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self._use_temp_file = True
        self._temp_file_extension = "xml"

    def report_belongs_to(self, **kwargs):
        if super().report_belongs_to(**kwargs):
            report_path = kwargs.get("report_path", "")
            with open(report_path) as f:
                output = f.read()
            return re.search("SSLyzeVersion", output) is not None
        return False

    def parseOutputString(self, output):
        parser = SslyzeXmlParser(output)
        host = parser.target[0].attrib['host']
        ip = parser.target[0].attrib['ip']
        port = parser.target[0].attrib['port']
        protocol = parser.target[0].attrib['tlsWrappedProtocol']
        cipher = parser.cipher_suite

        # Creating host
        host_id = self.createAndAddHost(ip)
        # Creating service CHANGE NAME
        service_id = self.createAndAddServiceToHost(
            host_id,
            name=protocol,
            protocol=protocol,
            ports=[port],
        )

        # Checking if certificate matches
        certificate = parser.certificate[0].attrib['certificateMatchesServerHostname']
        server_hostname = parser.certificate[0].attrib['serverHostname']
        if certificate.lower() == 'false':
            self.createAndAddVulnToService(
                host_id,
                service_id,
                name="Certificate mismatch",
                desc="Certificate does not match server hostname {}".format(server_hostname),
                severity="info")
        # Ciphers
        cipher = parser.cipher_suite

        for key in cipher:
            for value in cipher[key]:
                self.createAndAddVulnToService(
                    host_id,
                    service_id,
                    name=value,
                    desc="In protocol [{}], weak cipher suite: {}".format(key, value),
                    severity="low")

        # Heartbleed
        heartbleed = parser.heart_bleed

        if heartbleed[0][0].attrib['isVulnerable'].lower() == 'true':
            self.createAndAddVulnToService(
                host_id,
                service_id,
                name="OpenSSL Heartbleed",
                desc="OpenSSL Heartbleed is vulnerable",
                severity="critical")

        # OpenSsl CCS Injection
        openssl_ccs = parser.open_ssl_ccs

        if openssl_ccs[0][0].attrib['isVulnerable'].lower() == 'true':
            self.createAndAddVulnToService(
                host_id,
                service_id,
                name="OpenSSL CCS Injection",
                desc="OpenSSL CCS Injection is vulnerable",
                severity="medium")


def createPlugin(ignore_info=False):
    return SslyzePlugin(ignore_info=ignore_info)
