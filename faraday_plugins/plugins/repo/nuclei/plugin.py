"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import subprocess # nosec
import re
import sys
import json
from abc import ABC, abstractmethod
from typing import Dict, Any
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


class NucleiReportParser(ABC):
    """Abstract base class for Nuclei report parsers."""

    def __init__(self, vuln_dict: Dict[str, Any]):
        self.vuln_dict = vuln_dict
        self.info = vuln_dict.get('info', {})

    @abstractmethod
    def get_impact(self) -> str:
        """Extract impact information from the vulnerability as text for technical data."""
        pass

    @abstractmethod
    def get_resolution(self) -> str:
        """Extract resolution information from the vulnerability."""
        pass

    @staticmethod
    @abstractmethod
    def can_parse(vuln_dict: Dict[str, Any]) -> bool:
        """Check if this parser can handle the given vulnerability format."""
        pass


class NucleiV3Parser(NucleiReportParser):
    """Parser for Nuclei v3.x JSON format."""

    def get_impact(self) -> str:
        """Extract impact from Nuclei 3.x format (descriptive text) for technical data."""
        impacted_text = self.info.get('impact', '')
        if isinstance(impacted_text, str):
            return impacted_text.strip()
        return ''

    def get_resolution(self) -> str:
        """Extract resolution from top-level remediation field."""
        return self.info.get('remediation', '')

    @staticmethod
    def can_parse(vuln_dict: Dict[str, Any]) -> bool:
        """Check for Nuclei 3.x specific fields."""
        info = vuln_dict.get('info', {})
        return 'impact' in info or 'remediation' in info


class NucleiV2Parser(NucleiReportParser):
    """Parser for Nuclei v2.x JSON format."""

    def get_impact(self) -> str:
        """Extract impact from Nuclei 2.x format for technical data."""
        metadata = self.info.get('metadata', {})
        impacted_str = metadata.get('impact', '')
        if isinstance(impacted_str, str):
            return impacted_str.strip()
        return ''

    def get_resolution(self) -> str:
        """Extract resolution from metadata field."""
        metadata = self.info.get('metadata', {})
        return metadata.get('resolution', '')

    @staticmethod
    def can_parse(vuln_dict: Dict[str, Any]) -> bool:
        """Default parser - can handle any format as fallback."""
        return True


def _get_parser(vuln_dict: Dict[str, Any]) -> NucleiReportParser:
    """Factory method to select the appropriate Nuclei parser.

    Args:
        vuln_dict: The vulnerability dictionary from Nuclei output

    Returns:
        An instance of the appropriate parser for the detected version
    """

    parsers = [NucleiV3Parser, NucleiV2Parser]

    for parser_class in parsers:
        if parser_class.can_parse(vuln_dict):
            return parser_class(vuln_dict)

    # Fallback to V2 parser if no specific parser matches
    return NucleiV2Parser(vuln_dict)


class NucleiPlugin(PluginMultiLineJsonFormat):
    """ Handle the Nuclei tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "nuclei"
        self.name = "Nuclei"
        self.plugin_version = "1.1.0"
        self.version = "3.4.10"
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
            info = vuln_dict.get('info', {})

            reference = info.get('reference', [])
            if not reference:
                reference = []
            else:
                if isinstance(reference, str):
                    if re.match('^- ', reference):
                        reference = list(filter(None, [re.sub('^- ', '', elem) for elem in reference.split('\n')]))
                    else:
                        reference = [reference]
            references = info.get('references', [])
            if references:
                if isinstance(references, str):
                    if re.match('^- ', references):
                        references = list(filter(None, [re.sub('^- ', '', elem) for elem in references.split('\n')]))
                    else:
                        references = [references]
            else:
                references = []

            cve = info.get('classification', {}).get('cve-id', [])
            if cve:
                cve = [x.upper() for x in cve]

            vector_string = info.get('classification', {}).get('cvss-metrics')
            cvss3 = {"vector_string": vector_string} if vector_string else None
            cwe = info.get('classification', {}).get('cwe-id', [])
            if cwe:
                cwe = [x.upper() for x in cwe]
            #capec = vuln_dict['info'].get('metadata', {}).get('capec', [])
            #if isinstance(capec, str):
            #    capec = capec.upper().split(',')

            refs = sorted(list(set(reference + references)))
            refs = list(filter(None, refs))
            tags = info.get('tags', [])
            if isinstance(tags, str):
                tags = tags.split(',')



            parser = _get_parser(vuln_dict)
            impact = parser.get_impact()
            resolution = parser.get_resolution()

            easeofresolution = info.get('metadata', {}).get('easeofresolution', None)

            request = vuln_dict.get('request', '')
            if request:
                method = request.split(" ")[0]
            else:
                method = ""

            data = [f"Matched: {vuln_dict.get('matched-at')}",
                    f"Tags: {info.get('tags', '')}",
                    f"Template ID: {vuln_dict.get('template-id', '')}"]

            # Add impact to technical data if present
            if impact:
                data.append(f"Impact: {impact}")

            name = info.get("name")
            run_date = vuln_dict.get('timestamp')
            if run_date:
                run_date = parse(run_date)
            self.createAndAddVulnWebToService(
                host_id,
                service_id,
                name=name,
                desc=info.get("description", name),
                ref=refs,
                severity=info.get('severity'),
                tags=tags,
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
