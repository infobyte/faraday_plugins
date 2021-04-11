"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re
from faraday_plugins.plugins.plugin import PluginBase

__author__ = "Ezequiel Tavella - @EzequielTBH"
__copyright__ = "Copyright 2015, @EzequielTBH"
__credits__ = "Ezequiel Tavella - @EzequielTBH"
__license__ = "GPL v3"
__version__ = "1.0.0"


class traceroutePlugin(PluginBase):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Traceroute"
        self.name = "Traceroute"
        self.plugin_version = "1.0.0"
        self.command_string = ""
        self._command_regex = re.compile(r'^(traceroute|traceroute6)\s+.*?')

    def parseOutputString(self, output):

        print("[*]Parsing Output...")

        # Check no results.
        if not output.startswith("traceroute to"):
            return

        # Check if last parameter is host or ( packetlen or data size).
        parameters = self.command_string.split(' ')
        parameters.reverse()
        hostName = parameters[0]

        try:
            int(hostName)
            # No exception => host is the next item.
            hostName = parameters[1]
        except:
            pass

        # Add host and note with output of traceroute.
        hostId = self.createAndAddHost(hostName)
        self.createAndAddNoteToHost(hostId, "Traceroute Results", output)

        print("[*]Parse finished, API faraday called...")

    def processCommandString(self, username, current_path, command_string):
        super().processCommandString(username, current_path, command_string)
        self.command_string = command_string
        return None


def createPlugin(ignore_info=False):
    return traceroutePlugin(ignore_info=ignore_info)


