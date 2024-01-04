"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import subprocess # nosec
import re
import sys
import json
from dateutil.parser import parse
from urllib.parse import urlparse
from packaging import version
from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat

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
        self.plugin_version = "1.0.3"
        self.version = "2.5.5"
        self.json_keys = {"matched-at", "template-id", "host"}
        self._command_regex = re.compile(r'^(sudo nuclei|nuclei|\.\/nuclei|^.*?nuclei)\s+.*?')
        self.xml_arg_re = re.compile(r"^.*(-o\s*[^\s]+).*$")
        self._use_temp_file = True
        self._temp_file_extension = "json"

    def parseOutputString(self, output, debug=False):
        for vuln_json in filter(lambda x: x != '', output.split("\n")):
            vuln_dict = json.loads(vuln_json)
            host = vuln_dict.get('host')
            url_data = urlparse(host)
            if url_data.hostname is None:
                host = 'http://' + host
                url_data = urlparse(host)
            ip = vuln_dict.get("ip")
            if not ip:
                ip = self.resolve_hostname(url_data.hostname)
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
            matched = vuln_dict.get('matched-at', '')
            if matched:
                matched_data = urlparse(matched)
            else:
                print('Version not supported, use nuclei 2.5.3 or higher')
                sys.exit(1)
            reference = vuln_dict["info"].get('reference', [])
            if not reference:
                reference = []
            else:
                if isinstance(reference, str):
                    if re.match('^- ', reference):
                        reference = list(filter(None, [re.sub('^- ', '', elem) for elem in reference.split('\n')]))
                    else:
                        reference = [reference]
            references = vuln_dict["info"].get('references', [])
            if references:
                if isinstance(references, str):
                    if re.match('^- ', references):
                        references = list(filter(None, [re.sub('^- ', '', elem) for elem in references.split('\n')]))
                    else:
                        references = [references]
            else:
                references = []

            cve = vuln_dict['info'].get('classification', {}).get('cve-id', [])
            if cve:
                cve = [x.upper() for x in cve]

            vector_string = vuln_dict['info'].get('classification', {}).get('cvss-metrics')
            cvss3 = {"vector_string": vector_string} if vector_string else None
            cwe = vuln_dict['info'].get('classification', {}).get('cwe-id', [])
            if cwe:
                cwe = [x.upper() for x in cwe]
            #capec = vuln_dict['info'].get('metadata', {}).get('capec', [])
            #if isinstance(capec, str):
            #    capec = capec.upper().split(',')

            refs = sorted(list(set(reference + references)))
            refs = list(filter(None, refs))

            tags = vuln_dict['info'].get('tags', [])
            if isinstance(tags, str):
                tags = tags.split(',')

            impact = {}
            impacted = vuln_dict['info'].get('metadata', {}).get('impact')
            if isinstance(impacted, str):
                for x in impacted.split(','):
                    impact[x] = True

            resolution = vuln_dict['info'].get('metadata', {}).get('resolution', '')
            easeofresolution = vuln_dict['info'].get('metadata', {}).get('easeofresolution', None)

            request = vuln_dict.get('request', '')
            if request:
                method = request.split(" ")[0]
            else:
                method = ""

            data = [f"Matched: {vuln_dict.get('matched-at')}",
                    f"Tags: {vuln_dict['info'].get('tags', '')}",
                    f"Template ID: {vuln_dict.get('template-id', '')}"]

            name = vuln_dict["info"].get("name")
            run_date = vuln_dict.get('timestamp')
            if run_date:
                run_date = parse(run_date)
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
                cve=cve,
                # TODO CVSSv2, CVSSv3, CWE and CAPEC
                #cvssv2=cvssv2,
                #cvssv3=cvssv3,
                cwe=cwe,
                #capec=capec,
                website=host,
                request=request,
                response=vuln_dict.get('response', '').replace('\x00', ''),
                method=method,
                query=matched_data.query,
                params=matched_data.params,
                path=matched_data.path,
                data="\n".join(data),
                external_id=f"NUCLEI-{vuln_dict.get('template-id', '')}",
                run_date=run_date,
                cvss3=cvss3
            )

    def processCommandString(self, username, current_path, command_string):
        super().processCommandString(username, current_path, command_string)
        arg_match = self.xml_arg_re.match(command_string)
        if arg_match is None:
            return re.sub(r"(^.*?nuclei)",
                          r"\1 --json -irr -o %s" % self._output_file_path,
                          command_string)
        else:
            return re.sub(arg_match.group(1),
                          r" --json -irr -o %s" % self._output_file_path,
                          command_string)

    def canParseCommandString(self, current_input):
        can_parse = super().canParseCommandString(current_input)
        if can_parse:
            try:
                proc = subprocess.Popen([self.command, '-version'], stderr=subprocess.PIPE) # nosec
                output = proc.stderr.read()
                match = re.search(r"Current Version: ([0-9.]+)", output.decode('UTF-8'))
                if match:
                    nuclei_version = match.groups()[0]
                    return version.parse(nuclei_version) >= version.parse("2.5.3")
                else:
                    return False
            except Exception as e:
                return False


def createPlugin(*args, **kwargs):
    return NucleiPlugin(*args, **kwargs)
