"""
Faraday Penetration Test IDE
Copyright (C) 2025  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re
import json
from math import floor
from faraday_plugins.plugins.plugin import PluginJsonFormat


__author__ = "Dante Acosta"
__copyright__ = "Copyright (c) 2025, Infobyte LLC"
__credits__ = ["Dante Acosta"]
__version__ = "1.0.0"
__maintainer__ = "Dante"
__email__ = "dacosta@infobytesec.com"
__status__ = "Development"


code_map = {
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


class DirsearchPluginJSON(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "dirsearchjson"
        self.name = "dirsearch Plugin for JSON output"
        self.plugin_version = "0.4.3"
        self.version = "1.0.0"
        self.json_keys = {'results', 'info'}
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        json_report = json.loads(output)
        if not json_report:
            return None

        regex_map = {}
        data_regroup = {}

        for result in json_report.get('results', []):
            loc = result.get('url', None)
            if loc is None:
                continue

            status = result.get('status', None)
            if status is None:
                continue
            status_round = floor(status / 100) * 100
            if status_round == 400:
                continue

            if loc not in regex_map:
                regex_res = re.findall("((?:http|https):\\/\\/(\\S*?)(?::[0-9]*|)(?:\\/|$))", loc)
                if (isinstance(regex_res, list) and len(regex_res) > 0 and isinstance(regex_res[0], tuple) and
                        len(regex_res[0]) == 2 and regex_res[0][1]):
                    regex_map[loc] = regex_res[0][1]
                if not regex_map[loc] in data_regroup:
                    data_regroup[regex_map[loc]] = {}

            if status_round not in data_regroup[regex_map[loc]]:
                data_regroup[regex_map[loc]][status_round] = (
                    f"One or more endpoints returned **{int(status_round/100)}xx** :\n"
                )

            cl = result.get('content-length', None)
            ct = result.get('content-type', None)
            red = result.get('redirect') or None

            data_regroup[regex_map[loc]][status_round] += (
                f"- [{status}] **{loc}**{(' with content type *'+ct+'*') if ct is not None else ''}"
                f"{(' ('+str(cl)+' bytes)') if cl is not None else ''}"
                f"{(' redirects to ['+red+']('+red+')') if red is not None else ''}\n"
            )
        for host in data_regroup:
            h = self.createAndAddHost(host, hostnames=[host])
            for code in data_regroup[host]:
                self.createAndAddVulnToHost(
                    h,
                    f"Returned {int(code/100)}xx",
                    desc=data_regroup[host][code],
                    severity="info",
                    confirmed=True
                )

def createPlugin(*args, **kwargs):
    return DirsearchPluginJSON(*args, **kwargs)
