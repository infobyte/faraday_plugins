"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re
import os

from faraday_plugins.plugins.plugin import PluginBase


__author__ = "Facundo de Guzmán, Esteban Guillardoy"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Facundo de Guzmán", "Esteban Guillardoy"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Federico Kirschbaum"
__email__ = "fedek@infobytesec.com"
__status__ = "Development"


class CmdWhoisPlugin(PluginBase):
    """
    This plugin handles whois command.
    Basically detects if user was able to connect to a device
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "whois"
        self.name = "Whois"
        self.plugin_version = "0.0.1"
        self.version = "5.0.20"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(r'^whois\s+.*?')
        self._host_ip = None
        self._info = 0
        self._completition = {
            "": "whois [OPTION]... OBJECT...",
            "-l": "one level less specific lookup [RPSL only]",
            "-L": "find all Less specific matches",
            "-m": "find first level more specific matches",
            "-M": "find all More specific matches",
            "-c": "find the smallest match containing a mnt-irt attribute",
            "-x": "exact match [RPSL only]",
            "-d": "return DNS reverse delegation objects too [RPSL only]",
            "-i": "-i ATTR[,ATTR]...      do an inverse lookup for specified ATTRibutes",
            "-T": "-T TYPE[,TYPE]...      only look for objects of TYPE",
            "-K": "only primary keys are returned [RPSL only]",
            "-r": "turn off recursive lookups for contact information",
            "-R": "force to show local copy of the domain object even if it contains referral",
            "-a": "search all databases",
            "-s": "-s SOURCE[,SOURCE]...  search the database from SOURCE",
            "-g": "-g SOURCE:FIRST-LAST   find updates from SOURCE from serial FIRST to LAST",
            "-t": "-t TYPE request template for object of TYPE",
            "-v": "-v TYPE request verbose template for object of TYPE",
            "-q": "-q [version|sources|types]  query specified server info [RPSL only]",
            "-F": "fast raw output (implies -r)",
            "-h": "-h HOST connect to server HOST",
            "-p": "-p PORT connect to PORT",
            "-H": "hide legal disclaimers",
            "--verbose": "explain what is being done",
            "--help": "display this help and exit",
            "--version": "output version information and exit",
        }

    def processCommandString(self, username, current_path, command_string):
        self.command_string = command_string
        super().processCommandString(username, current_path, command_string)

    def parseOutputString(self, output):
        matches = re.findall(r"Name Server:\s*(.*)\s*", output)
        if not matches:
            matches = re.findall(r"nserver:\s*(.*)\s*", output)

        if not matches:
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', self.command_string)
            if not ip:
                url = self.command_string.replace('whois ', '')
                ip = [self.resolve_hostname(url)]
            matches_descr = re.findall(r"descr:\s*(.*)\s*", output)

            matches_netname = re.findall(r"NetName:\s*(.*)\s*", output)
            if not matches_netname:
                matches_netname = re.findall(r"netname:\s*(.*)\s*", output)
            matches_ref = re.findall(r"Ref:\s*(.*)\s*", output)
            desc = ""
            ref = []
            os_name = "unknown"

            for md in matches_descr:
                desc = md.strip()

            for mr in matches_ref:
                ref.append(mr.strip())

            for osname in matches_netname:
                os_name = osname.strip()
            self.createAndAddHost(
                ip[0],
                os_name,
                hostnames=[ref],
                description=desc
            )
        else:
            for m in matches:
                m = m.strip()
                url = re.findall(r'https?://[^\s<>"]+|.[^\s<>"]+', str(m))
                ip = self.resolve_hostname(url[0])
                self.createAndAddHost(
                    ip,
                    hostnames=[m]
                )
            matches_domain = re.findall(r"Domain Name:\s*(.*)\s*", output)
            for md in matches_domain:
                md = md.strip()
                ip = self.resolve_hostname(md)
                self.createAndAddHost(
                    ip,
                    hostnames=[md]
                )
        return True


def createPlugin(*args, **kwargs):
    return CmdWhoisPlugin(*args, **kwargs)
