"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class WhatWebJsonParser:

    def __init__(self, json_output):
        list_data = json.loads(json_output)
        self.host_whatweb = []
        for info in list_data:
            try:
                server_info = info['plugins']['HTTPServer']
            except KeyError:
                server_info = {}

            try:
                ip_info = info['plugins']['IP']
            except KeyError:
                ip_info = {}

            try:
                country_info = info['plugins']['Country']
            except KeyError:
                country_info = {}

            whatweb_data = {
                "url": info.get('target', None),
                "os": None if not server_info else server_info.get('os', None),
                "os_detail": "Unknown" if not server_info else server_info.get('string', 'Unknown'),
                "ip": ['0.0.0.0'] if ip_info is None else ip_info.get('string', None),
                "country": "" if country_info is None else country_info.get('string', "")
            }
            self.host_whatweb.append(whatweb_data)


class WhatWebPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "whatweb"
        self.name = "WhatWebPlugin"
        self.plugin_version = "0.1"
        self.version = "0.0.1"
        self.json_keys = {'target', 'http_status', 'plugins'}


    def parseOutputString(self, output):
        parser = WhatWebJsonParser(output)
        for whatweb_data in parser.host_whatweb:
            desc = f"{whatweb_data['os_detail']} - {whatweb_data['country']}"
            if whatweb_data['os'] is None:
                datail_os = "Unknown"
            else:
                datail_os = whatweb_data['os'][0]

            self.createAndAddHost(whatweb_data['ip'][0],
                                  os=datail_os,
                                  hostnames=whatweb_data['url'],
                                  description=desc)


def createPlugin(*args, **kwargs):
    return WhatWebPlugin(*args, **kwargs)
