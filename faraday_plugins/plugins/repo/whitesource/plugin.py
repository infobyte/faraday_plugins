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


__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class WhitesourcePlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "whitesource"
        self.name = "whitesource"
        self.plugin_version = "0.1"
        self.version = "3.4.5"
        self.json_keys = [
            {"vulnerabilities"},
            {"libraries", "projectVitals"},        # Mend CLI generated report
            {"response", "additionalData", "supportToken"},  # Mend SCA Platform API v3
        ]
        self.filter_keys = {"host"}

    def parseOutputString(self, output):
        parser = json.loads(output)
        # Mend CLI report — uses `libraries[]` with embedded `vulnerabilities[]`.
        if isinstance(parser.get("libraries"), list) and "projectVitals" in parser:
            self._parse_cli_report(parser)
            return
        # Mend SCA Platform API v3 — wrapper with `response[]` of findings.
        if "response" in parser and isinstance(parser["response"], list):
            self._parse_platform_api_v3(parser)
            return
        if parser.get('vulnerabilities'):
            for vulnerability in parser['vulnerabilities']:
                cvss3 = {}
                cvss2 = {}
                if 'project' in vulnerability:
                    application_name = vulnerability.get('project')
                    host_id = self.createAndAddHost(application_name)
                    data = ''
                    for key, value in vulnerability['library'].items():
                        data += f'{key}: {value} \n'
                    refs = []
                    if "scoreMetadataVector" in vulnerability:
                        cvss3["vector_string"] = vulnerability['scoreMetadataVector']
                    if 'topFix' in vulnerability:
                        refs.append(f"URL: {vulnerability['topFix']['url']}")
                        self.createAndAddVulnToHost(host_id,
                                                    name=vulnerability['name'],
                                                    desc=vulnerability['description'],
                                                    data=data,
                                                    resolution=vulnerability['topFix']['fixResolution'],
                                                    ref=refs,
                                                    severity=vulnerability['severity'],
                                                    cve=[vulnerability['name']],
                                                    cvss2=cvss2,
                                                    cvss3=cvss3)
                    else:
                        self.createAndAddVulnToHost(host_id,
                                                    name=vulnerability['name'],
                                                    desc=vulnerability['description'],
                                                    data=data,
                                                    ref=refs,
                                                    severity=vulnerability['severity'],
                                                    cvss2=cvss2,
                                                    cvss3=cvss3)
                elif 'namespace' in vulnerability:
                    host_id = self.createAndAddHost(vulnerability['namespace'])
                    service_id = self.createAndAddServiceToHost(
                        host_id,
                        vulnerability['featurename'],
                        ports=0
                    )
                    self.createAndAddVulnToService(
                        host_id,
                        service_id,
                        name=vulnerability['vulnerability'],
                        desc=vulnerability['description'],
                        ref=[vulnerability['link']],
                        severity=vulnerability['severity'],
                        cve=[vulnerability['vulnerability']]
                    )

                elif 'package' in vulnerability:
                    host_id = self.createAndAddHost(vulnerability['feed_group'])
                    service_id = self.createAndAddServiceToHost(
                        host_id,
                        vulnerability['package'],
                        ports=0
                    )
                    self.createAndAddVulnToService(
                        host_id,
                        service_id,
                        name=f'{vulnerability["vuln"]} {vulnerability["package_name"]}',
                        ref=[vulnerability['url']],
                        severity=vulnerability['severity'],
                        cve=[vulnerability['vuln']]
                    )

    # ---- Mend CLI generated report ---------------------------------------

    def _parse_cli_report(self, data):
        project = (data.get("projectVitals") or {}).get("name") or "mend-project"
        for library in data.get("libraries") or []:
            vulns = library.get("vulnerabilities") or []
            if not vulns:
                continue
            lib_name = library.get("name", "unknown")
            host_id = self.createAndAddHost(
                lib_name,
                description=f"Mend project: {project} ({library.get('type', '')})",
            )
            for v in vulns:
                cvss3 = {}
                if v.get("scoreMetadataVector"):
                    cvss3["vector_string"] = v["scoreMetadataVector"]
                if isinstance(v.get("score"), (int, float)):
                    cvss3.setdefault("base_score", v["score"])
                fix = (v.get("topFix") or {})
                refs = []
                if fix.get("url"):
                    refs.append(fix["url"])
                self.createAndAddVulnToHost(
                    host_id,
                    name=v.get("name", "Mend finding"),
                    desc=v.get("description", "") or "",
                    severity=(v.get("severity") or "info").lower(),
                    cve=[v.get("name")] if str(v.get("name", "")).upper().startswith("CVE-") else [],
                    cvss3=cvss3,
                    ref=refs,
                    resolution=fix.get("fixResolution", "") or "",
                    external_id=v.get("name", ""),
                    data=f"Library: {lib_name}\nMatch type: {library.get('matchType', '')}",
                )

    # ---- Mend SCA Platform API v3 ----------------------------------------

    def _parse_platform_api_v3(self, data):
        for finding in data.get("response") or []:
            if finding.get("type") and finding["type"] != "SECURITY_VULNERABILITY":
                continue
            comp = finding.get("component") or {}
            cve_name = finding.get("name", "")
            host_label = comp.get("name") or comp.get("uuid") or "unknown"
            host_id = self.createAndAddHost(
                host_label,
                description=comp.get("description", "") or "",
            )
            severity = (finding.get("severity") or comp.get("severity") or "info").lower()
            cvss3 = {}
            if finding.get("cvss3Vector"):
                cvss3["vector_string"] = finding["cvss3Vector"]
            if isinstance(finding.get("cvss3Score"), (int, float)):
                cvss3["base_score"] = finding["cvss3Score"]
            top_fix = finding.get("topFix") or {}
            refs = []
            if top_fix.get("url"):
                refs.append(top_fix["url"])
            self.createAndAddVulnToHost(
                host_id,
                name=cve_name or "Mend finding",
                desc=finding.get("description", "") or "",
                severity=severity,
                cve=[cve_name] if cve_name.upper().startswith("CVE-") else [],
                cvss3=cvss3,
                ref=refs,
                resolution=top_fix.get("fixResolution", "") or "",
                external_id=str(finding.get("uuid", cve_name)),
                data=f"Component: {host_label}\n"
                     f"Library type: {comp.get('libraryType', '')}",
            )


def createPlugin(*args, **kwargs):
    return WhitesourcePlugin(*args, **kwargs)
