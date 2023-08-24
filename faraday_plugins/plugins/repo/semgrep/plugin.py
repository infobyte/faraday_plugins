"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json

from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"


class SemgrepPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Semgrep_JSON"
        self.name = "Semgrep Json"
        self.plugin_version = "1.0.0"
        self.json_keys = {'errors', 'paths', 'results', 'version'}

    def parseOutputString(self, output):
        json_semgrep = json.loads(output)
        results = json_semgrep.get("results")
        severity_mapper = {
            "ERROR": "critical",
            "WARNING": "high",
            "INFO": "info"
        }
        if not results:
            return
        for result in results:
            path = result.get('path')
            host_id = self.createAndAddHost(
                name=path
            )
            extra = result.get('extra')
            if not extra:
                continue
            line_start = result.get("start",{}).get("line")
            service_id = self.createAndAddServiceToHost(
                host_id=host_id,
                name=f"Line {line_start}",
                ports=int(line_start)
            )
            if line_start:
                path += str(line_start)

            severity = severity_mapper[extra.get("severity", "INFO")]
            lines = extra.get("lines","")
            refs = []
            desc = extra.get("message")
            metadata = extra.get("metadata")
            if not metadata:
                continue
            cwe = []
            for i in metadata.get("cwe",[]):
                cwe.append(i.split(":")[0])
            references = metadata.get("references")
            if isinstance(references,list):
                refs += references
            elif isinstance(references, str):
                refs.append(references)
            owasp = metadata.get("owasp")
            if isinstance(owasp,list):
                refs += owasp
            elif isinstance(owasp,str):
                refs.append(owasp)
            bandit_code = metadata.get("bandit-code")
            if bandit_code:
                references.append(f"Bandit code {bandit_code}")
            data = f"Path: {path}\nLines: {lines}"
            self.createAndAddVulnToService(
                host_id=host_id,
                service_id=service_id,
                name=desc[:50],
                desc=desc,
                severity=severity,
                cwe=cwe,
                ref=refs,
                data=data
            )


def createPlugin(*args, **kwargs):
    return SemgrepPlugin(*args, **kwargs)
