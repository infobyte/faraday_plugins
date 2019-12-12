"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from faraday_plugins.plugins.plugin import PluginBase
import socket
import re
import os

current_path = os.path.abspath(os.getcwd())


class AmapPlugin(PluginBase):
    """ Example plugin to parse amap output."""

    def __init__(self):
        super().__init__()
        self.id = "Amap"
        self.name = "Amap Output Plugin"
        self.plugin_version = "0.0.3"
        self.version = "5.4"
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(r'^(amap|sudo amap).*?')
        self._hosts = []

    def parseOutputString(self, output, debug=False):
        # if not os.path.exists(self._file_output_path):
        #     return False
        #
        # if not debug:
        #     with open(self._file_output_path) as f:
        #         output = f.read()

        services = {}
        for line in output.split('\n'):
            if line.startswith('#'):
                continue

            fields = self.get_info(line)

            if len(fields) < 6:
                continue

            address = fields[0]
            h_id = self.createAndAddHost(address)

            port = fields[1]
            protocol = fields[2]
            port_status = fields[3]

            identification = fields[5]
            printable_banner = fields[6]

            if port in services.keys():
                if identification != 'unidentified':
                    services[port][5] += ', ' + identification
            else:
                services[port] = [
                    address,
                    port,
                    protocol,
                    port_status,
                    None,
                    identification,
                    printable_banner,
                    None]

            args = {}

            if self.args.__getattribute__("6"):
                self.ip = self.get_ip_6(self.args.m)
                args['ipv6_address'] = address
            else:
                self.ip = self.getAddress(self.args.m)
                args['ipv4_address'] = address

            if address != self.args.m:
                args['hostname_resolution'] = [self.args.m]

            i_id = self.createAndAddInterface(h_id, name=address, **args)

        for key in services:
            service = services.get(key)
            self.createAndAddServiceToInterface(
                h_id,
                i_id,
                service[5],
                service[2],
                ports=[service[1]],
                status=service[3],
                description=service[6])

        return True

    file_arg_re = re.compile(r"^.*(-o \s*[^\s]+\s+(?:-m|)).*$")

    def get_info(self, data):
        if self.args.__getattribute__("6"):
            f = re.search(
                r"^\[(.*)\]:(.*):(.*):(.*):(.*):(.*):(.*):(.*)",
                data)

            return [
                f.group(1),
                f.group(2),
                f.group(3),
                f.group(4),
                f.group(5),
                f.group(6),
                f.group(7),
                f.group(8)] if f else []

        else:
            return data.split(':')

    def get_ip_6(self, host, port=0):
        alladdr = socket.getaddrinfo(host, port)
        ip6 = list(filter(
            lambda x: x[0] == socket.AF_INET6,
            alladdr))

        return ip6[0][4][0]

    def getAddress(self, hostname):
        """
        Returns remote IP address from hostname.
        """
        try:
            return socket.gethostbyname(hostname)
        except socket.error as msg:
            return hostname

    def setHost(self):
        pass


def createPlugin():
    return AmapPlugin()

# I'm Py3
