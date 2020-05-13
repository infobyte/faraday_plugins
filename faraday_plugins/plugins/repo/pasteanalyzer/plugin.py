"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""

# Author: @EzequielTBH
from builtins import str

from faraday_plugins.plugins.plugin import PluginBase
import json
import re

__author__ = "@EzequielTBH"
__copyright__ = "Copyright 2015, @EzequielTBH"
__credits__ = "@EzequielTBH"
__license__ = "GPL v3"
__version__ = "1.0.0"


class pasteAnalyzerPlugin(PluginBase):

    def __init__(self):
        super().__init__()
        self.id = "pasteAnalyzer"
        self.name = "pasteAnalyzer JSON Output Plugin"
        self.plugin_version = "1.0.0"
        self.command_string = ""
        self._command_regex = re.compile(
            r'^(pasteAnalyzer|python pasteAnalyzer.py|\./pasteAnalyzer.py|sudo python pasteAnalyzer.py|sudo \./pasteAnalyzer.py)\s+.*?')

    def parseOutputString(self, output):
        # Generating file name with full path.
        indexStart = self.command_string.find("-j") + 3
        fileJson = self.command_string[
            indexStart:self.command_string.find(" ", indexStart)]
        fileJson = self._current_path + "/" + fileJson
        try:
            with open(fileJson, "r") as fileJ:
                results = json.loads(fileJ.read())
        except Exception as e:
            return
        if results == []:
            return
        # Configuration initial.
        hostId = self.createAndAddHost("pasteAnalyzer")
        interfaceId = self.createAndAddInterface(hostId, "Results")
        serviceId = self.createAndAddServiceToInterface(
            hostId,
            interfaceId,
            "Web",
            "TcpHTTP",
            ['80']
        )

        # Loading results.
        for i in range(0, len(results), 2):

            data = results[i + 1]
            description = ""

            for element in data:

                # Is Category
                if type(element) == str: #TODO bte arrray decode
                    description += element + ": "

                # Is a list with results!
                else:
                    for element2 in element:
                        description += "\n" + element2
            self.createAndAddVulnWebToService(
                hostId,
                serviceId,
                results[i],
                description
            )

    def processCommandString(self, username, current_path, command_string):
        super().processCommandString(username, current_path, command_string)

        if command_string.find("-j") < 0:
            command_string += " -j JSON_OUTPUT "

        self.command_string = command_string

        return command_string


def createPlugin():
    return pasteAnalyzerPlugin()

# I'm Py3
