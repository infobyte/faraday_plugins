"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from urllib.parse import urlsplit
from bs4 import BeautifulSoup
from lxml import etree

from faraday_plugins.plugins.plugin import PluginXMLFormat
from faraday_plugins.plugins.repo.invicti.DTO import Invicti

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"


class InvictiXmlParser:
    """
    The objective of this class is to parse a xml file generated by
    the acunetix tool.

    @param invicti_xml_filepath A proper xml generated by acunetix
    """

    def __init__(self, xml_output):

        tree = self.parse_xml(xml_output)
        self.invicti = Invicti(tree)

    @staticmethod
    def parse_xml(xml_output):
        """
        Open and parse an xml file.

        TODO: Write custom parser to just read the nodes that we need instead
        of reading the whole file.

        @return xml_tree An xml tree instance. None if error.
        """

        try:
            parser = etree.XMLParser(recover=True)
            tree = etree.fromstring(xml_output, parser=parser)
        except SyntaxError as err:
            print(f"SyntaxError: {err}. {xml_output}")
            return None

        return tree


class InvictiPlugin(PluginXMLFormat):
    """
    Example plugin to parse invicti output.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "invicti-enterprise"
        self.id = "Invicti"
        self.name = "Invicti XML Output Plugin"
        self.plugin_version = "1.0.0"
        self.version = "9"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self.target = None

    def parseOutputString(self, output):
        """
        This method will discard the output the shell sends, it will read it
        from the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """
        parser = InvictiXmlParser(output)
        url = urlsplit(parser.invicti.target.url)
        ip = self.resolve_hostname(url.netloc)
        h_id = self.createAndAddHost(ip)
        s_id = self.createAndAddServiceToHost(h_id, url.scheme, ports=433)
        for vulnerability in parser.invicti.vulnerabilities:
            vuln = {
                "name": vulnerability.name,
                "severity": vulnerability.severity,
                "confirmed": vulnerability.confirmed,
                "desc": BeautifulSoup(vulnerability.description, features="lxml").text,
                "path": vulnerability.url.replace(parser.invicti.target.url, ""),
                "external_id": vulnerability.look_id
            }
            if vulnerability.remedial_procedure:
                vuln["resolution"] = BeautifulSoup(vulnerability.remedial_procedure, features="lxml").text
            if vulnerability.classification:
                references = []
                if vulnerability.classification.owasp:
                    references.append("OWASP" + vulnerability.classification.owasp)
                if vulnerability.classification.wasc:
                    references.append("WASC" + vulnerability.classification.wasc)
                if vulnerability.classification.cwe:
                    vuln["cwe"] = "CWE-" + vulnerability.classification.cwe
                if vulnerability.classification.capec:
                    references.append("CAPEC" + vulnerability.classification.capec)
                if vulnerability.classification.pci32:
                    references.append("PCI32" + vulnerability.classification.pci32)
                if vulnerability.classification.hipaa:
                    references.append("HIPAA" + vulnerability.classification.hipaa)
                if vulnerability.classification.owasppc:
                    references.append("OWASPPC" + vulnerability.classification.owasppc)
                if vulnerability.classification.cvss3.node is not None:
                    vuln["cvss3"] = {"vector_string": vulnerability.classification.cvss3.vector}
                vuln["ref"] = references
            if vulnerability.http_response.node is not None:
                vuln["response"] = vulnerability.http_response.content
            if vulnerability.http_request.node is not None:
                vuln["request"] = vulnerability.http_request.content
            self.createAndAddVulnWebToService(h_id, s_id, **vuln)


def createPlugin(*args, **kwargs):
    return InvictiPlugin(*args, **kwargs)
