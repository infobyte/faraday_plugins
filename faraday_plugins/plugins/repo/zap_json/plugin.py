"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re
from json import loads

from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.repo.zap_json.DTO import ZapJsonParser

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"


def split_and_strip_tags(data):
    """
    Split string using closing html tags
    then remove them
    @return list Stripped string
    """
    r = []
    split = re.compile('</.*?>')
    for i in re.split(split, data)[:-1]:
        r += [strip_tags(i)]
    return r


def strip_tags(data):
    """
    Remove html tags from a string
    @return Stripped string
    """
    clean = re.compile('<.*?>')
    return re.sub(clean, '', data)


class ZapJsonPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "OWASPZAPReport"
        self.id = "Zap_Json"
        self.name = "Zap Json Output Plugin"
        self.plugin_version = "0.1"
        self.version = "2.11.1"
        self.framework_version = "1.0.0"
        self.options = None
        self._temp_file_extension = "json"
        self.json_keys = {'@version'}

    def parseOutputString(self, output):
        """
        This method will discard the output the shell sends, it will read it
        from the json where it expects it to be present.
        """

        parser = ZapJsonParser(loads(output))

        for site in parser.sites:
            ip = self.resolve_hostname(site.host)
            host = []
            if site.host != ip:
                host = [site.host]

            if site.ssl == "true":
                service = "https"
            else:
                service = "http"

            h_id = self.createAndAddHost(ip, hostnames=host)

            s_id = self.createAndAddServiceToHost(h_id, service, "tcp", ports=[site.port], status='open')

            for item in site.alerts:
                for instance in item.instances:
                    data = f"URL:\n {instance.uri.uri}\n"
                    if instance.evidence:
                        data += f" Parameter:\n {instance.param}\n Evidence:\n {instance.evidence}"
                    elif instance.attack and instance.param:
                        data += f" Payload:\n {instance.param} = {instance.attack}"
                    elif instance.param:
                        data += f" Parameter:\n {instance.param}"

                    ref = []
                    cwe = []
                    if item.reference:
                        ref += split_and_strip_tags(item.reference)
                    if item.cwe:
                        cwe += [f"CWE-{item.cwe}"]
                    if item.wasc:
                        ref += [f"WASC:{item.wasc}"]

                    self.createAndAddVulnWebToService(
                        h_id,
                        s_id,
                        item.name,
                        strip_tags(item.desc),
                        website=site.name,
                        query=instance.uri.query,
                        severity=item.riskcode,
                        path=instance.uri.path,
                        params=', '.join(instance.uri.params),
                        method=instance.method,
                        ref=ref,
                        resolution=strip_tags(item.solution),
                        data=data,
                        pname=instance.param,
                        external_id="ZAP-" + str(item.plugin_id),
                        cwe=cwe
                    )

        del parser


def createPlugin(*args, **kwargs):
    return ZapJsonPlugin(*args, **kwargs)
