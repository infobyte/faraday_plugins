"""
Faraday Penetration Test IDE
Copyright (C) 2025  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re
import json
import tldextract
from math import floor
from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat


__author__ = "Dante Acosta"
__copyright__ = "Copyright (c) 2025, Infobyte LLC"
__credits__ = ["Dante Acosta"]
__version__ = "1.0.0"
__maintainer__ = "Dante Acosta"
__email__ = "dacosta@infobytesec.com"
__status__ = "Development"


def extract_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"


class SubfinderPluginJSON(PluginMultiLineJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "subfinderjson"
        self.name = "Subfinder Plugin for JSON output"
        self.plugin_version = "2.6.8"
        self.version = "1.0.0"
        self.json_keys = {'host', 'input'}
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        json_lines = output.splitlines()
        for line in json_lines:
            try:
                json_line = json.loads(line)
            except json.decoder.JSONDecodeError:
                return None
            hostname = json_line['host']
            domain = extract_domain(hostname)
            self.createAndAddHost(hostname, hostnames=[domain])


def createPlugin(*args, **kwargs):
    return SubfinderPluginJSON(*args, **kwargs)
