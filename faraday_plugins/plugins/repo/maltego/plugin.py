"""
Faraday Penetration Test IDE
Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import xml.etree.ElementTree as ET
import zipfile

from faraday_plugins.plugins.plugin import PluginZipFormat

__author__ = "Ezequiel Tavella"
__copyright__ = "Copyright (c) 2015, Infobyte LLC"
__credits__ = ["Ezequiel Tavella"]
__license__ = ""
__version__ = "1.0.1"
__maintainer__ = "Ezequiel Tavella"
__status__ = "Development"


def readMtgx(mtgl_file):
    maltego_file_graph = "Graphs/Graph1.graphml"
    xml_graph = ET.parse(mtgl_file.open(maltego_file_graph))
    mtgl_file.close()
    return xml_graph


def readMtgl(mtgl_file):
    try:
        maltego_file_company = "Entities/maltego.Company.entity"
        maltego_file_dns = "Entities/maltego.DNSName.entity"
        maltego_file_domain = "Entities/maltego.Domain.entity"
        maltego_file_email = "Entities/maltego.EmailAddress.entity"
        maltego_file_ipv4 = "Entities/maltego.IPv4Address.entity"
        maltego_file_location = "Entities/maltego.Location.entity"
        maltego_file_mxrecord = "Entities/maltego.MXRecord.entity"
        maltego_file_nsrecord = "Entities/maltego.NSRecord.entity"
        maltego_file_organization = "Entities/maltego.Organization.entity"
        maltego_file_person = "Entities/maltego.Person.entity"
        maltego_file_number = "Entities/maltego.PhoneNumber.entity"
        maltego_file_website = "Entities/maltego.Website.entity"
        check_files = {}

        if maltego_file_company in mtgl_file.namelist():
            xml_company = ET.parse(mtgl_file.open(maltego_file_company))
            check_files.update({"company": xml_company})

        if maltego_file_dns in mtgl_file.namelist():
            xml_dns = ET.parse(mtgl_file.open(maltego_file_dns))
            check_files.update({"domain": xml_dns})

        if maltego_file_domain in mtgl_file.namelist():
            xml_domain = ET.parse(mtgl_file.open(maltego_file_domain))
            check_files.update({"domain": xml_domain})

        if maltego_file_email in mtgl_file.namelist():
            xml_email = ET.parse(mtgl_file.open(maltego_file_email))
            check_files.update({"email": xml_email})

        if maltego_file_ipv4 in mtgl_file.namelist():
            xml_ipv4 = ET.parse(mtgl_file.open(maltego_file_ipv4))
            check_files.update({"ipv4": xml_ipv4})

        if maltego_file_location in mtgl_file.namelist():
            xml_location = ET.parse(mtgl_file.open(maltego_file_location))
            check_files.update({"location": xml_location})

        if maltego_file_mxrecord in mtgl_file.namelist():
            xml_mxrecord = ET.parse(mtgl_file.open(maltego_file_mxrecord))
            check_files.update({"mxrecord": xml_mxrecord})

        if maltego_file_nsrecord in mtgl_file.namelist():
            xml_nsrecord = ET.parse(mtgl_file.open(maltego_file_nsrecord))
            check_files.update({"nsrecord": xml_nsrecord})

        if maltego_file_organization in mtgl_file.namelist():
            xml_organization = ET.parse(mtgl_file.open(maltego_file_organization))
            check_files.update({"organization": xml_organization})

        if maltego_file_person in mtgl_file.namelist():
            xml_person = ET.parse(mtgl_file.open(maltego_file_person))
            check_files.update({"person": xml_person})

        if maltego_file_number in mtgl_file.namelist():
            xml_number = ET.parse(mtgl_file.open(maltego_file_number))
            check_files.update({"number": xml_number})

        if maltego_file_website in mtgl_file.namelist():
            xml_web = ET.parse(mtgl_file.open(maltego_file_website))
            check_files.update({"web": xml_web})

    except zipfile.BadZipFile:
        return None

    mtgl_file.close()
    return check_files


class Host:

    def __init__(self):
        self.ip = ""
        self.node_id = ""
        self.dns_name = set()
        self.website = ""
        self.netblock = ""
        self.location = ""
        self.mx_record = ""
        self.ns_record = ""


class MaltegoParser:

    def __init__(self, xml_file, extension, resolve_hostname):

        self.resolve_hostname = resolve_hostname
        if extension == '.mtgx':
            self.xml = readMtgx(xml_file)
            self.nodes = self.xml.findall(
                "{http://graphml.graphdrawing.org/xmlns}graph/"
                "{http://graphml.graphdrawing.org/xmlns}node")
            self.edges = self.xml.findall(
                "{http://graphml.graphdrawing.org/xmlns}graph/"
                "{http://graphml.graphdrawing.org/xmlns}edge")

            self.list_hosts = []
            self.relations = {}
        elif extension == '.mtgl':
            self.xml = readMtgl(xml_file)

    def getRelations(self):
        """
        Get relations between nodes.
        Two ways: Source-> Target
        Source <- Target
        """
        for edge in self.edges:

            source = edge.get("source")
            target = edge.get("target")

            if source not in self.relations:
                self.relations.update({source: [target]})

            if target not in self.relations:
                self.relations.update({target: [source]})

            values = self.relations[source]
            values.append(target)
            self.relations.update({source: values})

            values = self.relations[target]
            values.append(source)
            self.relations.update({target: values})

    def getIpAndId(self, node):
        # Find node ID and maltego entity
        node_id = node.get("id")
        entity = node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity")

        # Check if is IPv4Address
        if entity.get("type") not in ("maltego.IPv4Address", "maltego.Domain", "maltego.Website"):
            return None

        # Get IP value
        value = entity.find(
            "{http://maltego.paterva.com/xml/mtgx}Properties/"
            "{http://maltego.paterva.com/xml/mtgx}Property/"
            "{http://maltego.paterva.com/xml/mtgx}Value")
        if entity.get("type") in ("maltego.Domain", "maltego.Website"):
            ip = self.resolve_hostname(value.text)
            hostname = value.text
        else:
            ip = value.text
            hostname = None
        return {"node_id": node_id, "ip": ip, "hostname": hostname}

    def getNode(self, node_id):

        # Get node, filter by id
        for node in self.nodes:

            if node.get("id") == node_id:
                return node

    def getType(self, node):

        # Get type of this node
        entity = node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity")

        return entity.get("type")

    def getWebsite(self, target_node):

        # Parse Website Entity
        result = {"name": "", "ssl_enabled": "", "urls": ""}

        props = target_node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity/"
            "{http://maltego.paterva.com/xml/mtgx}Properties")

        for prop in props:

            name_property = prop.get("name")
            value = prop.find(
                "{http://maltego.paterva.com/xml/mtgx}Value").text

            if name_property == "fqdn":
                result["name"] = value
            elif name_property == "website.ssl-enabled":
                result["ssl_enabled"] = value
            elif name_property == "URLS":
                result["urls"] = value

        return result

    def getNetBlock(self, target_node):

        # Parse Netblock Entity
        result = {"ipv4_range": "", "network_owner": "", "country": ""}

        props = target_node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity/"
            "{http://maltego.paterva.com/xml/mtgx}Properties")

        for prop in props:

            name_property = prop.get("name")
            value = prop.find(
                "{http://maltego.paterva.com/xml/mtgx}Value").text

            if name_property == "ipv4-range":
                result["ipv4_range"] = value
            elif name_property == "description":
                result["network_owner"] = value
            elif name_property == "country":
                result["country"] = value

        return result

    def getLocation(self, target_node):

        # Parse Location Entity
        result = {"name": "", "area": "", "country_code": "", "longitude": "", "latitude": "", "area_2": ""}

        # Get relations with other nodes
        node_relations = self.relations[target_node.get("id")]

        # Find location node based in relation with netblock node.
        located = False
        for node_id in node_relations:

            target_node = self.getNode(node_id)
            if self.getType(target_node) == "maltego.Location":
                located = True
                break

        if not located:
            return None

        # Get properties and update data
        props = target_node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity/"
            "{http://maltego.paterva.com/xml/mtgx}Properties")

        for prop in props:

            name_property = prop.get("name")
            value = prop.find(
                "{http://maltego.paterva.com/xml/mtgx}Value").text

            if name_property == "location.name":
                result["name"] = value
            elif name_property == "location.area":
                result["area"] = value
            elif name_property == "countrycode":
                result["country_code"] = value
            elif name_property == "longitude":
                result["longitude"] = value
            elif name_property == "latitude":
                result["latitude"] = value
            elif name_property == "area":
                result["area_2"] = value

        return result

    def getValue(self, target_node):

        # Parse Entity
        result = {"value": ""}

        value = target_node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity/"
            "{http://maltego.paterva.com/xml/mtgx}Properties/"
            "{http://maltego.paterva.com/xml/mtgx}Property/"
            "{http://maltego.paterva.com/xml/mtgx}Value")

        result["value"] = value.text
        return result

    def parse(self):

        self.getRelations()

        for node in self.nodes:
            # Get IP Address if not continue with other node...
            result = self.getIpAndId(node)
            if not result:
                continue

            # Create host with values by default
            host = Host()
            host.ip = result.get("ip")
            host.node_id = result.get("node_id")
            if result.get("hostname"):
                host.dns_name.add(result.get("hostname"))
            # Get relations with other nodes
            node_relations = self.relations[host.node_id]

            for node_id in node_relations:

                # Get target node and type of node.
                target_node = self.getNode(node_id)
                target_type = self.getType(target_node)

                # Check type of node y add data to host...
                if target_type in ("maltego.DNSName", "maltego.Domain"):
                    host.dns_name.add(self.getValue(target_node)['value'])
                elif target_type == "maltego.Website":
                    host.website = self.getWebsite(target_node)
                elif target_type == "maltego.Netblock":
                    host.netblock = self.getNetBlock(target_node)
                    # Get location based in relation: netblock -> location
                    host.location = self.getLocation(target_node)
                elif target_type == "maltego.MXRecord":
                    host.mx_record = self.getValue(target_node)
                elif target_type == "maltego.NSRecord":
                    host.ns_record = self.getValue(target_node)

            self.list_hosts.append(host)

        return self.list_hosts

    def getInfoMtgl(self, xml, name):
        sample_value = xml.findall(f'Properties/Fields/Field[@name="{name}"]')
        for data in sample_value:
            mtgl_data = data.find('SampleValue').text
        return mtgl_data


class MaltegoPlugin(PluginZipFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "maltego"
        self.id = "Maltego"
        self.name = "Maltego MTGX & MTGL Output Plugin"
        self.plugin_version = "1.0.1"
        self.version = "Maltego 3.6"
        self.framework_version = "1.0.0"
        self.extension = [".mtgl", ".mtgx"]
        self.files_list = {"Graphs/Graph1.graphml", "Entities/maltego.Company.entity",
                           "Entities/maltego.DNSName.entity", "Entities/maltego.Domain.entity",
                           "Entities/maltego.EmailAddress.entity", "Entities/maltego.IPv4Address.entity",
                           "Entities/maltego.Location.entity", "Entities/maltego.MXRecord.entity",
                           "Entities/maltego.Organization.entity", "Entities/maltego.NSRecord.entity",
                           "Entities/maltego.Person.entity", "Entities/maltego.PhoneNumber.entity",
                           "Entities/maltego.Website.entity", "Entities/maltego.Hash.entity",
                           "Entities/maltego.hashtag.entity", "Entities/maltego.TwitterUserList.entity"}

    def parseOutputString(self, output):
        if 'Graphs/Graph1.graphml' in output.namelist():
            maltego_parser = MaltegoParser(output, self.extension[1], resolve_hostname=self.resolve_hostname)
            hosts = maltego_parser.parse()
            if not hosts:
                self.logger.warning("No hosts data found in maltego report")
                pass
            else:
                for host in hosts:
                    if host.ip is None:
                        ip = '0.0.0.0'
                        self.logger.warning("Unknown IP")
                    else:
                        ip = host.ip
                    host_id = self.createAndAddHost(ip, hostnames=list(host.dns_name))
                    # Create note with NetBlock information
                    if host.netblock:
                        try:
                            text = f'Network owner:\n {host.netblock["network_owner"]} ' \
                                   f'Country:\n {host.netblock["country"]}'
                        except TypeError:
                            text = "unknown"

                        self.createAndAddNoteToHost(host_id=host_id, name="Netblock Information",
                                                    text=text.encode('ascii', 'ignore'))

                    # Create note with host location
                    if host.location:
                        try:
                            text = f'Location:\n {host.location["name"]} \nArea:\n {host.location["area"]} ' \
                                   f'\nArea 2:\n {host.location["area_2"]} ' \
                                   f'\nCountry_code:\n {host.location["country_code"]} ' \
                                   f'\nLatitude:\n {host.location["latitude"]} \nLongitude:\n {host.location["longitude"]}'
                        except TypeError:
                            text = "unknown"

                        self.createAndAddNoteToHost(host_id=host_id, name="Location Information",
                                                    text=text.encode('ascii', 'ignore'))

                    # Create service web server
                    if host.website:
                        try:
                            description = f'SSL Enabled: {host.website["ssl_enabled"]}'
                        except TypeError:
                            description = "unknown"

                        service_id = self.createAndAddServiceToHost(host_id=host_id, name=host.website["name"],
                                                                    protocol="TCP:HTTP", ports=[80],
                                                                    description=description)

                        try:
                            text = f'Urls: \n {host.website["urls"]}'
                            self.createAndAddNoteToService(host_id=host_id, service_id=service_id, name="URLs",
                                                           text=text.encode('ascii', 'ignore'))
                        except TypeError:
                            pass

                    if host.mx_record:
                        self.createAndAddServiceToHost(host_id=host_id, name=host.mx_record["value"], protocol="SMTP",
                                                       ports=[25], description="E-mail Server")

                    if host.ns_record:
                        self.createAndAddServiceToHost(host_id=host_id, name=host.ns_record["value"], protocol="DNS",
                                                       ports=[53], description="DNS Server")
        else:
            maltego_parser = MaltegoParser(output, self.extension[0], resolve_hostname=self.resolve_hostname)
            if not maltego_parser.xml.get('domain') or not maltego_parser.xml.get('ipv4'):
                return
            if maltego_parser.xml.get('domain'):
                hostnames = maltego_parser.getInfoMtgl(maltego_parser.xml['domain'], 'fqdn')
            else:
                hostnames = None
            if maltego_parser.xml.get('ipv4'):
                host_ip = maltego_parser.getInfoMtgl(maltego_parser.xml['ipv4'], 'ipv4-address')
                host_id = self.createAndAddHost(name=host_ip, hostnames=hostnames)
            else:
                host_ip = '0.0.0.0'
                host_id = self.createAndAddHost(name=host_ip, hostnames=hostnames)

            if maltego_parser.xml.get('location'):
                location_name = maltego_parser.getInfoMtgl(maltego_parser.xml['location'], 'location.name')
                location_area = maltego_parser.getInfoMtgl(maltego_parser.xml['location'], 'location.area')
                location_country = maltego_parser.getInfoMtgl(maltego_parser.xml['location'], 'countrycode')
                location_longitude = maltego_parser.getInfoMtgl(maltego_parser.xml['location'], 'longitude')
                location_latitude = maltego_parser.getInfoMtgl(maltego_parser.xml['location'], 'latitude')
                text = f'Location:\n {location_name} \n Area:\n {location_area} \nCountry_code:\n {location_country} ' \
                       f'\nLatitude:\n {location_latitude} \nLongitude:\n {location_longitude}'

                self.createAndAddNoteToHost(host_id=host_id, name="Location Information",
                                            text=text.encode('ascii', 'ignore'))
            else:
                self.createAndAddNoteToHost(host_id=host_id, name="Location Information", text="unknown")

            if maltego_parser.xml.get('web'):
                web_name = maltego_parser.getInfoMtgl(maltego_parser.xml['web'], 'fqdn')
                text = f'Urls: \n {web_name}'
                web_port = maltego_parser.getInfoMtgl(maltego_parser.xml['web'], 'ports')
                if web_port is None:
                    web_port = 80

                web_ssh = maltego_parser.getInfoMtgl(maltego_parser.xml['web'], 'website.ssl-enabled')
                description = f'SSL Enabled: {web_ssh}'

                service_id = self.createAndAddServiceToHost(host_id=host_id, name=web_name, protocol="TCP:HTTP",
                                                            ports=web_port, description=description)

                self.createAndAddNoteToService(host_id=host_id, service_id=service_id, name="URLs",
                                               text=text.encode('ascii', 'ignore'))

            if maltego_parser.xml.get('mxrecord'):
                mx_name = maltego_parser.getInfoMtgl(maltego_parser.xml['mxrecord'], 'fqdn')

                self.createAndAddServiceToHost(host_id=host_id, name=mx_name, protocol="SMTP", ports=[25],
                                               description="E-mail Server")

            if maltego_parser.xml.get('nsrecord'):
                ns_name = maltego_parser.getInfoMtgl(maltego_parser.xml['nsrecord'], 'fqdn')
                self.createAndAddServiceToHost(host_id=host_id, name=ns_name, protocol="DNS", ports=[53],
                                               description="DNS Server")


def createPlugin(*args, **kwargs):
    return MaltegoPlugin(*args, **kwargs)
