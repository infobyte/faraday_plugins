"""
Updated by Mike Zhong, 25 Oct 2017.

Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re

__author__ = u"Andres Tarantini"
__copyright__ = u"Copyright (c) 2015 Andres Tarantini"
__credits__ = [u"Andres Tarantini"]
__license__ = u"MIT"
__version__ = u"0.0.1"
__maintainer__ = u"Andres Tarantini"
__email__ = u"atarantini@gmail.com"
__status__ = u"Development"

from faraday_plugins.plugins.plugin import PluginBase
from faraday_plugins.plugins.plugins_utils import resolve_hostname


class DigPlugin(PluginBase):
    """
    Handle DiG (http://linux.die.net/man/1/dig) output
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "dig"
        self.name = "DiG"
        self.plugin_version = "0.0.1"
        self.version = "9.9.5-3"
        self._command_regex = re.compile(r'^(dig)\s+.*?')

    def parseOutputString(self, output):
        # Ignore all lines that start with ";"
        parsed_output = [line for line in output.splitlines() if line and line[
            0] != u";"]
        if not parsed_output:
            return True

        # Parse results
        results = []
        answer_section_columns = [u"domain",
                                  u"ttl", u"class", u"type", u"data"]
        for line in parsed_output:
            line_split = line.split() # the first 4 elements are domain, ttl, class, type; everything else data
            results.append(dict(zip(answer_section_columns, line_split[:4] + [line_split[4:]] )))

        # Create hosts is results information is relevant
        try:
            for result in results:
                relevant_types = [u"A", u"AAAA", u"MX", u"NS", u"SOA", u"TXT"]
                # TODO implement more types from https://en.wikipedia.org/wiki/List_of_DNS_record_types

                if result.get(u"type") in relevant_types:

                    # get domain
                    domain = result.get(u"domain")


                    # get IP address (special if type "A")
                    if result.get(u"type") == u"A": # A = IPv4 address from dig
                        ip_address = result.get(u"data")[0]
                    else:                           # if not, from socket
                        ip_address = resolve_hostname(domain)

                    # Create host
                    host_id = self.createAndAddHost(ip_address, hostnames=[domain])


                    # all other TYPES that aren't 'A' and 'AAAA' are dealt here:
                    if result.get(u"type") == u"MX": # Mail exchange record
                        mx_priority = result.get(u"data")[0]
                        mx_record = result.get(u"data")[1]

                        service_id = self.createAndAddServiceToHost(
                            host_id=host_id,
                            name=mx_record,
                            protocol="SMTP",
                            ports=[25],
                            description="E-mail Server")

                        text = "Priority: " + mx_priority
                        self.createAndAddNoteToService(
                            host_id=host_id,
                            service_id=service_id,
                            name="priority",
                            text=text.encode('ascii', 'ignore'))

                    elif result.get(u"type") == u"NS": # Name server record
                        ns_record = result.get(u"data")[0]
                        self.createAndAddServiceToHost(
                            name=ns_record,
                            protocol="DNS",
                            ports=[53],
                            description="DNS Server")

                    elif result.get(u"type") == u"SOA": # Start of Authority Record
                        ns_record = result.get(u"data")[0] # primary namer server
                        responsible_party = result.get(u"data")[1] # responsible party of domain
                        timestamp = result.get(u"data")[2]
                        refresh_zone_time = result.get(u"data")[3]
                        retry_refresh_time = result.get(u"data")[4]
                        upper_limit_time = result.get(u"data")[5]
                        negative_result_ttl = result.get(u"data")[6]

                        service_id = self.createAndAddServiceToHost(
                            host_id=host_id,
                            name=ns_record,
                            protocol="DNS",
                            ports=[53],
                            description="Authority Record")

                        text = (
                            "Responsible Party: " + responsible_party +
                            "\nTimestep: " + timestamp +
                            "\nTime before zone refresh (sec): " + refresh_zone_time +
                            "\nTime before retry refresh (sec): " + retry_refresh_time +
                            "\nUpper Limit before Zone is no longer authoritive (sec): " + upper_limit_time +
                            "\nNegative Result TTL: " + negative_result_ttl)

                        self.createAndAddNoteToService(
                            host_id=host_id,
                            service_id=service_id,
                            name="priority",
                            text=text.encode('ascii', 'ignore'))

                    elif result.get(u"type") == u"TXT": # TXT record
                        text = " ".join(result.get(u"data")[:])
                        self.createAndAddNoteToHost(
                            host_id=host_id,
                            name="TXT Information",
                            text=text.encode('ascii', 'ignore'))

        except Exception as ex:
            print("some part of the dig plug-in caused an error! Please check repo/dig/plugin.py")
            return False

        return True


def createPlugin(ignore_info=False):
    return DigPlugin(ignore_info=ignore_info)


