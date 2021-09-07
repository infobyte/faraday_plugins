"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import socket
import re
import json
import dateutil
from collections import defaultdict
from urllib.parse import urlparse
from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat
from faraday_plugins.plugins.plugins_utils import resolve_hostname

__author__ = "Nicolas Rebagliati"
__copyright__ = "Copyright (c) 2021, Infobyte LLC"
__credits__ = ["Nicolas Rebagliati"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Nicolas Rebagliati"
__email__ = "nrebagliati@infobytesec.com"
__status__ = "Development"


class NucleiPlugin(PluginMultiLineJsonFormat):
    """ Handle the Nuclei tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "nuclei"
        self.name = "Nuclei"
        self.plugin_version = "1.0.1"
        self.version = "2.3.8"
        self.json_keys = {"matched", "templateID", "host"}
        self._command_regex = re.compile(r'^(sudo nuclei|nuclei|\.\/nuclei|^.*?nuclei)\s+.*?')
        self.xml_arg_re = re.compile(r"^.*(-o\s*[^\s]+).*$")
        self._use_temp_file = True
        self._temp_file_extension = "json"

    def parseOutputString(self, output, debug=False):
        for vuln_json in filter(lambda x: x != '', output.split("\n")):
            vuln_dict = json.loads(vuln_json)
            host = vuln_dict.get('host')
            url_data = urlparse(host)
            ip = vuln_dict.get("ip", resolve_hostname(url_data.hostname))
            host_id = self.createAndAddHost(
                name=ip,
                hostnames=[url_data.hostname])
            port = url_data.port
            if not port:
                if url_data.scheme == 'https':
                    port = 443
                else:
                    port = 80
            service_id = self.createAndAddServiceToHost(
                host_id,
                name=url_data.scheme,
                ports=port,
                protocol="tcp",
                status='open',
                version='',
                description='web server')
            matched = vuln_dict.get('matched')
            matched_data = urlparse(matched)
            reference = vuln_dict["info"].get('reference', [])
            if reference:
                if isinstance(reference, str):
                    if re.match('^- ', reference):
                        reference = list(filter(None, [re.sub('^- ','', elem) for elem in reference.split('\n')]))
                    else:
                        reference = [reference]
            references = vuln_dict["info"].get('references', [])
            if references:
                if isinstance(references, str):
                    if re.match('^- ', references):
                        references = list(filter(None, [re.sub('^- ','', elem) for elem in references.split('\n')]))
                    else:
                        references = [references]
            cwe = vuln_dict['info'].get('cwe', [])
            capec = vuln_dict['info'].get('capec', [])
            refs = sorted(list(set(reference + references + cwe + capec)))
            tags = vuln_dict['info'].get('tags', '').split(',')
            impact = vuln_dict['info'].get('impact')
            resolution = vuln_dict['info'].get('resolution', '')
            easeofresolution = vuln_dict['info'].get('easeofresolution')
            request = vuln_dict.get('request', '')
            if request:
                method = request.split(" ")[0]
            else:
                method = ""
            data = [f"Matched: {vuln_dict.get('matched')}",
                    f"Tags: {vuln_dict['info'].get('tags')}",
                    f"Template ID: {vuln_dict['templateID']}"]

            name = vuln_dict["info"].get("name")
            run_date = vuln_dict.get('timestamp')
            if run_date:
                run_date = dateutil.parser.parse(run_date)
            self.createAndAddVulnWebToService(
                host_id,
                service_id,
                name=name,
                desc=vuln_dict["info"].get("description", name),
                ref=refs,
                severity=vuln_dict["info"].get('severity'),
                tags=tags,
                impact=impact,
                resolution=resolution,
                easeofresolution=easeofresolution,
                website=host,
                request=request,
                response=vuln_dict.get('response', ''),
                method=method,
                query=matched_data.query,
                params=matched_data.params,
                path=matched_data.path,
                data="\n".join(data),
                external_id=f"NUCLEI-{vuln_dict.get('templateID', '')}",
                run_date=run_date
            )
    
    def processCommandString(self, username, current_path, command_string):
        """
        Adds the -oX parameter to get xml output to the command string that the
        user has set.
        """
        super().processCommandString(username, current_path, command_string)
        arg_match = self.xml_arg_re.match(command_string)
        if arg_match is None:
            return re.sub(r"(^.*?nuclei)",
                          r"\1 --json -irr -o %s" % self._output_file_path,
                          command_string)
        else:
            return re.sub(arg_match.group(1),
                          r"--json -irr -o %s" % self._output_file_path,
                          command_string)            




def createPlugin(ignore_info=False):
    return NucleiPlugin(ignore_info=ignore_info)


