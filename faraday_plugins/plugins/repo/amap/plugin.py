"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import argparse
import re
import shlex
import socket

from faraday_plugins.plugins.plugin import PluginBase


class AmapPlugin(PluginBase):
    """ Example plugin to parse amap output."""

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Amap"
        self.name = "Amap Output Plugin"
        self.plugin_version = "0.0.3"
        self.version = "5.4"
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(r'^(amap|sudo amap)\s+.*?')
        self._use_temp_file = True
        self._hosts = []
        self.args = None

    def parseOutputString(self, output):
        services = {}
        for line in output.split('\n'):
            if line.startswith('#'):
                continue
            fields = self.get_info(line)
            if len(fields) < 6:
                continue
            address = fields[0]
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

            if address != self.args.m:
                hostnames = [self.args.m]
            else:
                hostnames = None
            h_id = self.createAndAddHost(address, hostnames=hostnames)

        for key in services:
            service = services.get(key)
            self.createAndAddServiceToHost(
                h_id,
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

    def processCommandString(self, username, current_path, command_string):
        """
        Adds the -m parameter to get machine readable output.
        """
        super().processCommandString(username, current_path, command_string)
        arg_match = self.file_arg_re.match(command_string)
        parser = argparse.ArgumentParser()
        parser.add_argument('-6', action='store_true')
        parser.add_argument('-o')
        parser.add_argument('-m')
        if arg_match is None:
            final = re.sub(
                r"(^.*?amap)",
                r"\1 -o %s -m " % self._output_file_path,
                command_string)
        else:
            final = re.sub(
                arg_match.group(1),
                r"-o %s -m " % self._output_file_path,
                command_string)

        cmd = shlex.split(re.sub(r'\-h|\-\-help', r'', final))
        if "-6" in cmd:
            cmd.remove("-6")
            cmd.insert(1, "-6")

        if len(cmd) > 4:
            try:
                self.args, unknown = parser.parse_known_args(cmd)
            except SystemExit:
                pass

        return final


def createPlugin(*args, **kwargs):
    return AmapPlugin(*args, **kwargs)
