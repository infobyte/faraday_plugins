"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re
from json import loads

from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.repo.zap_json.DTO import ZapJsonParser
from faraday_plugins.plugins.plugins_utils import resolve_hostname

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"


def strip_tags(data):
    """
    Remove html tags from a string
    @return Stripped string
    """
    clean = re.compile('<.*?>')
    return re.sub(clean, '', data)


class ZapJsonPlugin(PluginJsonFormat):
    """
    Example plugin to parse zap output.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "OWASPZAPReport"
        self.id = "Zap_Json"
        self.name = "Zap Json Output Plugin"
        self.plugin_version = "0.1"
        self.version = "2.10.0"
        self.framework_version = "1.0.0"
        self.options = None
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        """
        This method will discard the output the shell sends, it will read it
        from the xml where it expects it to be present.
        """

        parser = ZapJsonParser(loads(output))

        for site in parser.sites:
            ip = resolve_hostname(site.host)
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
                    if item.reference:
                        ref += item.reference
                    if item.cwe:
                        ref += f"CWE:{item.cwe}"
                    if item.wasc:
                        ref += f"WASC:{item.wasc}"

                    self.createAndAddVulnWebToService(
                        h_id,
                        s_id,
                        item.name,
                        strip_tags(item.desc),
                        website=site.name,
                        query=instance.uri.query,
                        severity=item.riskcode,
                        path=instance.uri.path,
                        params=instance.param,
                        method=instance.method,
                        ref=item.reference,
                        resolution=strip_tags(item.solution),
                        data=data,
                        pname=instance.param,
                        external_id="ZAP-" + str(item.plugin_id)
                    )

        del parser


def createPlugin(ignore_info=False):
    return ZapJsonPlugin(ignore_info=ignore_info)
