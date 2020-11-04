from faraday_plugins.plugins.plugin import PluginXMLFormat
import xml.etree.ElementTree as ET

class BanditPlugin(PluginXMLFormat):
    """
    Example plugin to parse bandit output.
    """

    def __init__(self):
        super().__init__()
        self.identifier_tag = 'bandit'
        self.extension = ".xml"
        self.id = "Bandit"
        self.name = "Bandit XML Output Plugin"
        self.plugin_version = "0.0.1"

    def parseOutputString(self, output):
        bp = BanditParser(output)
        bp.preload_hosts()

        for host in bp.hosts.keys():
            bp.hosts[host] = self.createAndAddHost(bp.hosts[host])

        for vuln in bp.vulns:
            self.createAndAddVulnToHost(
                host_id=bp.hosts[vuln['path']],
                name=vuln['name'],
                desc=vuln['issue_text'],
                ref=vuln['references'],
                severity=vuln['severity'],
            )

        return True

class BanditParser:
    """
    Parser for bandit on demand
    """

    def __init__(self, xml_output):
        self.hosts = {}
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

            vulns.append({'name': name, 'path':path, 'references': ref, 'issue_text': issue_text, 'severity': severity})

        return vulns

    def preload_hosts(self):
        for vuln in self.vulns:
            self.hosts[vuln['path']] = None

def createPlugin():
    return BanditPlugin()
