import xml.etree.ElementTree as ET

from faraday_plugins.plugins.plugin import PluginXMLFormat

__author__ = "@rfocke and @pasta <3"
__copyright__ = "Copyright (c) 2021, Faradaysec LLC"
__credits__ = ["Roberto Focke", "Javier Aguinaga"]
__license__ = "GPL"
__version__ = "0.8"
__mantainer__ = "@rfocke"
__status__ = "Development"


class VulnSoftNipper:
    def __init__(self, **kwargs):
        self.name = ''
        self.data = ''
        self.device = ''
        self.cvss2 = {}
        self.refs = []


class VulnerabilityNipper:
    def __init__(self, **kwargs):
        self.name = ''
        self.rating = ''
        self.recommendation = ''
        self.affected_devices = []
        self.section = ''
        self.name2 = ''
        self.data = ''
        self.recommendation2 = ''


class NipperParser:
    def __init__(self, output, debug=False):
        self.vulns_first = []
        self.vulns_audit = []
        self.vulns_thirds = []
        self.debug = debug

        self.tree = ET.fromstring(output)
        self.report_tree = self.tree.find(
            "report/part/[@index='2']/section/[@title='Recommendations']/table/[@title='Security Audit recommendations list']/tablebody")
        self.process_xml()

    def process_xml(self):
        if not self.report_tree:
            return

        for tablerow in self.report_tree:
            for i, tablecell in enumerate(tablerow.findall('tablecell')):
                if len(tablecell.findall('item')) == 1:
                    if i == 0:  # Item
                        vuln = VulnerabilityNipper()
                        vuln.name = tablecell.find('item').text
                    elif i == 1:  # Rating
                        vuln.rating = tablecell.find('item').text
                    elif i == 2:  # Recommendations
                        vuln.recommendation = tablecell.find('item').text
                    elif i == 3:  # Affected devices (with 1 element only)
                        vuln.affected_devices = []
                        vuln.affected_devices.append(tablecell.find('item').text)
                    elif i == 4:  # Section
                        subdetail = tablecell.find('item').text
                        vuln.section = subdetail

                        path = "./report/part/[@index='2']/section/[@index='" + subdetail + "']"
                        for detail in self.tree.findall(path):
                            # nombre de la vuln
                            vuln.name2 = detail.attrib.get('title')

                        if vuln.name2 != vuln.name:
                            pass

                        path = "./report/part/[@index='2']/section/[@index='" + subdetail + "']/section/[@index='" + subdetail + ".2']"
                        for detail in self.tree.findall(path):
                            # data de la vuln
                            vuln.data = detail.find('text').text

                        path = "./report/part/[@index='2']/section/[@index='" + subdetail + "']/section/[@index='" + subdetail + ".5']"
                        for detail in self.tree.findall(path):
                            # recomendacion de la vuln
                            vuln.recommendation2 = detail.find('text').text

                        self.vulns_first.append(vuln)  # <- GUARDADO
                elif len(tablecell.findall('item')) > 1 and i == 3:
                    # affected devices
                    vuln.affected_devices = []
                    for item in tablecell.findall('item'):
                        vuln.affected_devices.append(item.text)

        # parseo vuln de software
        report_tree = self.tree.find("./report/part/[@title='Vulnerability Audit']")
        for itemv in report_tree:
            vuln_soft = VulnSoftNipper()
            # nombre de la vuln

            vuln_soft.name = itemv.attrib.get('title')
            cvss2_vector = itemv.find('infobox/infodata/[@label="CVSSv2 Base"]')
            vuln_soft.cvss2["vector_string"] = cvss2_vector.text.split(' ')[0] if cvss2_vector is not None else None
            for itemvv in itemv:
                if itemvv.attrib.get('title') == 'Summary':
                    for i in itemvv:
                        # data de la vuln
                        vuln_soft.data = i.text
                if itemvv.attrib.get('title') == 'Affected Device':
                    for i in itemvv:
                        # data del device
                        aux = i.text.split('The')[1]
                        vuln_soft.device = aux.split(' may be affected by this security vulnerability')[0]
                if itemvv.attrib.get('title') == 'References':
                    # referencias de la vuln
                    vuln_soft.refs = []
                    for texto in itemvv.findall('list/listitem/weblink'):
                        vuln_soft.refs.append(texto.text)

            self.vulns_audit.append(vuln_soft)


class NipperPlugin(PluginXMLFormat):
    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.extension = ".xml"
        self.identifier_tag = "document"
        self.identifier_tag_attributes = {'nipperstudio'}
        self.id = "Nipper"
        self.name = "Nipper XML Output Plugin"
        self.plugin_version = "0.9"
        self.version = "0.9"
        self.framewor_version = "1.0.1"
        self.options = None

    def parseOutputString(self, output):
        parser = NipperParser(output, debug=False)
        for vuln in parser.vulns_first:
            for device in vuln.affected_devices:
                ip = self.resolve_hostname(device)
                h_id = self.createAndAddHost(ip, hostnames=device)
                self.createAndAddVulnToHost(h_id,
                                            name=vuln.name,
                                            desc=vuln.data,
                                            severity=vuln.rating,
                                            resolution=vuln.recommendation,
                                            data=vuln.data,
                                            ref=[],
                                            policyviolations=[],
                                            cve=[vuln.name]
                                            )
        for vuln in parser.vulns_audit:
            if vuln.data:
                ip = self.resolve_hostname(device)
                h_id = self.createAndAddHost(ip, hostnames=vuln.device)
                self.createAndAddVulnToHost(h_id,
                                            name=vuln.name,
                                            desc=vuln.data,
                                            severity='',
                                            resolution='',
                                            data=vuln.data,
                                            ref=vuln.refs,
                                            cve=[vuln.name],
                                            cvss2=vuln.cvss2
                                            )


def createPlugin(*args, **kwargs):
    return NipperPlugin(*args, **kwargs)
