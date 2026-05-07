"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import re
import socket
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat
from urllib.parse import urlparse


__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@faradaysec.com"
__status__ = "Development"


class SnykPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Snyk"
        self.name = "Snyk"
        self.plugin_version = "1"
        self.version = "1.1260.0"
        # Snyk single-project output carries `projectName`. The `--all-projects`
        # array shape doesn't auto-detect (the elements look very similar to
        # whitesource/mend reports); users must pass --plugin_id Snyk
        # explicitly. The parser handles both shapes.
        self.json_keys = {"vulnerabilities", "projectName"}
        self.filter_keys = {"imageDigest", "host"}

    def parseOutputString(self, output):
        parser = json.loads(output)
        # `snyk test --all-projects` emits a JSON array (one item per project).
        # Single-project runs emit a dict directly.
        projects = parser if isinstance(parser, list) else [parser]
        for project in projects:
            if not isinstance(project, dict):
                continue
            self._parse_project(project)

    def _parse_project(self, project):
        project_name = (project.get("projectName") or
                        project.get("displayTargetFile") or
                        project.get("path") or
                        "unknown")
        h_id = self.createAndAddHost(
            name=project_name,
            os=project.get("plataform") or project.get("platform") or "unknown",
        )
        for vulnerability in project.get("vulnerabilities", []) or []:
            identifiers = vulnerability.get("identifiers") or {}
            refs = []
            for ref in vulnerability.get("references", []) or []:
                if isinstance(ref, dict) and ref.get("url"):
                    refs.append(ref["url"])
                elif isinstance(ref, str):
                    refs.append(ref)
            vuln = {
                "name": vulnerability.get("title") or vulnerability.get("id") or "Snyk finding",
                "desc": vulnerability.get("description", "") or "",
                "severity": vulnerability.get("severity") or "info",
                "cve": identifiers.get("cve") or [],
                "cwe": identifiers.get("cwe") or [],
                "ref": refs,
                "external_id": vulnerability.get("id", "") or "",
            }
            cvss3 = vulnerability.get("CVSSv3")
            if cvss3 and isinstance(cvss3, str):
                vuln["cvss3"] = {"vector_string": cvss3}
            cvss_score = vulnerability.get("cvssScore")
            if cvss_score and "cvss3" in vuln:
                try:
                    vuln["cvss3"]["base_score"] = float(cvss_score)
                except (TypeError, ValueError):
                    pass
            self.createAndAddVulnToHost(host_id=h_id, **vuln)


def createPlugin(*args, **kwargs):
    return SnykPlugin(*args, **kwargs)
