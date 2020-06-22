"""
Faraday Penetration Test IDE
Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from faraday_plugins.plugins.plugin import PluginByExtension
import re
import os

__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Blas Moyano"
__status__ = "Development"


class MbsaParser:
    def __init__(self, xml_output):
        self.tree = self.parse_xml(xml_output)


class MaltegoPlugin(PluginByExtension):
    def __init__(self):
        super().__init__()
        self.id = "MBSA"
        self.name = "Microsoft Baseline Security Analyzer"
        self.plugin_version = "1.0.1"
        self.version = "MBSA 1.0"
        self.framework_version = "1.0.0"
        self.extension = ".log"

    def parseOutputString(self, output):
        print(type(output.find()))

        #parser = MbsaParser(output)


def createPlugin():
    return MaltegoPlugin()
