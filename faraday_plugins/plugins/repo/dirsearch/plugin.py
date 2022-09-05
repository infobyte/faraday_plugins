"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re
import json
import shlex
import argparse
import urllib.parse as urlparse
from faraday_plugins.plugins.plugin import PluginBase
from faraday_plugins.plugins.plugins_utils import get_vulnweb_url_fields


__author__ = "Matías Lang"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Matías Lang"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Matías Lang"
__email__ = "matiasl@infobytesec.com"
__status__ = "Development"


status_codes = {
    200: "OK", 201:  "Created", 202:  "Accepted",
    203: "Non-Authoritative Information", 204:  "No Content",
    205: "Reset Content", 206:  "Partial Content", 207:  "Multi-Status",
    208: "Already Reported", 226:  "IM Used", 300:  "Multiple Choices",
    301: "Moved Permanently", 302:  "Found", 303:  "See Other",
    304: "Not Modified", 305:  "Use Proxy", 306:  "Switch Proxy",
    307: "Temporary Redirect", 308:  "Permanent Redirect",
    400: "Bad Request", 401:  "Unauthorized", 402:  "Payment Required",
    403: "Forbidden", 404:  "Not Found", 405:  "Method Not Allowed",
    406: "Not Acceptable", 407:  "Proxy Authentication Required",
    408: "Request Timeout", 409:  "Conflict", 410:  "Gone",
    411: "Length Required", 412:  "Precondition Failed",
    413: "Payload Too Large", 414:  "URI Too Long",
    415: "Unsupported Media Type", 416:  "Range Not Satisfiable",
    417: "Expectation Failed", 418:  "I'm a teapot",
    421: "Misdirected Request", 422:  "Unprocessable Entity", 423:  "Locked",
    424: "Failed Dependency", 426:  "Upgrade Required",
    428: "Precondition Required", 429:  "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons", 500:  "Internal Server Error",
    501: "Not Implemented", 502:  "Bad Gateway", 503:  "Service Unavailable",
    504: "Gateway Timeout", 505:  "HTTP Version Not Supported",
    506: "Variant Also Negotiates", 507:  "Insufficient Storage",
    508: "Loop Detected", 510:  "Not Extended",
    511: "Network Authentication Required",
}


class DirsearchPlugin(PluginBase):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "dirsearch"
        self.name = "dirsearch"
        self.plugin_version = "0.0.1"
        self.version = "0.0.1"
        self._command_regex = re.compile(r'^(sudo )?(python[0-9\.]? )?(dirsearch\.py)\s+?')
        self.addSetting("Ignore 403", str, "1")
        self._use_temp_file = True
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        self.parse_json(output)

    @property
    def should_ignore_403(self):
        val = self.getSetting('Ignore 403')
        if not val or not int(val):
            return False
        return True

    def parse_json(self, contents):
        try:
            data = json.loads(contents)
        except ValueError:
            self.logger.error('Error parsing report. Make sure the file has valid '
                     'JSON', 'ERROR')
            return
        for (base_url, items) in data.items():
            base_split = urlparse.urlsplit(base_url)
            ip = self.resolve_hostname(base_split.hostname)
            h_id = self.createAndAddHost(ip, hostnames=[base_split.hostname])
            s_id = self.createAndAddServiceToHost(
                h_id,
                base_split.scheme,
                'tcp',
                [base_split.port],
                status="open")

            for item in items:
                self.parse_found_url(base_url, h_id, s_id, item)

    def parse_found_url(self, base_url, h_id, s_id, item):
        if self.should_ignore_403 and item['status'] == 403:
            return
        url = urlparse.urlsplit(urlparse.urljoin(base_url, item['path']))
        response = "HTTP/1.1 {} {}\nContent-Length: {}".format(
            item['status'], status_codes.get(item['status'], 'unknown'),
            item['content-length'])
        redirect = item.get('redirect')
        if redirect is not None:
            response += f'\nLocation: {redirect}'
        self.createAndAddVulnWebToService(
            h_id,
            s_id,
            name=f'Path found: {item["path"]} ({item["status"]})',
            desc=f"Dirsearch tool found the following URL: {url.geturl()}",
            severity="info",
            method='GET',
            response=response,
            **get_vulnweb_url_fields(url.geturl()))

    def processCommandString(self, username, current_path, command_string):
        parser = argparse.ArgumentParser(conflict_handler='resolve')
        parser.add_argument('-h', '--help', action='store_true')
        parser.add_argument('--json-report')
        args, unknown = parser.parse_known_args(shlex.split(command_string))
        if args.help:
            return None
        if args.json_report:
            # The user already defined a path to the JSON report
            self._output_file_path = args.json_report
            return None
        else:
            super().processCommandString(username, current_path, command_string)
            return f'{command_string} --json-report {self._output_file_path}'


def createPlugin(*args, **kwargs):
    return DirsearchPlugin(*args, **kwargs)
