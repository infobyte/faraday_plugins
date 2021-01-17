from faraday_plugins.plugins.plugin import PluginXMLFormat
import xml.etree.ElementTree as ET
import re

class BanditPlugin(PluginXMLFormat):
    """
    Example plugin to parse bandit output.
    """

    def __init__(self):
        super().__init__()
        self.identifier_tag = 'testsuite'
        self.extension = ".xml"
        self.id = "Bandit"
        self.name = "Bandit XML Output Plugin"
        self.plugin_version = "0.0.1"

    def report_belongs_to(self, **kwargs):
        if super().report_belongs_to(**kwargs):
            report_path = kwargs.get("report_path", "")
            with open(report_path) as f:
                output = f.read()
            return re.search("testsuite name=\"bandit\"", output) is not None
        return False

    def parseOutputString(self, output):
        bp = BanditParser(output)

        host = self._get_host_name()
        host_id = self.createAndAddHost(host)

        for vuln in bp.vulns:
            self.createAndAddVulnToHost(
                host_id=host_id,
                name=vuln['name'],
                desc=vuln['issue_text'],
                ref=vuln['references'],
                severity=vuln['severity'],
            )

        return True

    def _get_host_name(self):
        try:
            filename = self.vulns_data['command']['params'].split('/')[-1].lower()
            if filename.endswith('_faraday_bandit.xml'):
                return filename.lower().replace('_faraday_bandit.xml', '')

            return filename
        except:
            pass

        return 'bandit-report'


class BanditParser:
    """
    Parser for bandit on demand
    """

    def __init__(self, xml_output):
        self.vulns = self._parse_xml(xml_output)


    def _parse_xml(self, xml_output):
        vulns = []
        tree = ET.fromstring(xml_output)
        testcases = tree.findall('testcase')

        for testcase in testcases:
            error = testcase.find('error')
            name = testcase.attrib['name']
            path = testcase.attrib['classname']
            severity = error.attrib['type']
            issue_text = error.text
            more_info = error.attrib['more_info']
            ref = [more_info]

            vulns.append({'name': name, 'path': path, 'references': ref, 'issue_text': issue_text, 'severity': severity})

        return vulns

def createPlugin():
    return BanditPlugin()
