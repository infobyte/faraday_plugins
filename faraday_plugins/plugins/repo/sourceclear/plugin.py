"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

Veracode SCA / Sourceclear plugin.

This plugin handles all three JSON shapes Veracode SCA has emitted over the
years:

* Legacy ``{"metadata": ..., "records": [...]}`` — original sourceclear-cli
  format. Each record bundles its own vulnerabilities + libraries.
* Veracode REST API HAL response ``{"_embedded": {"issues": [...]}, ...}``.
* Modern findings list ``{"findings": [...]}`` — used by the unified
  Veracode platform export.

We dispatch on the top-level shape and emit one Faraday vuln per finding.
"""
import json
import re
from urllib.parse import urlparse

from faraday_plugins.plugins.plugin import PluginJsonFormat


__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2019, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.2.0"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


# Veracode platform uses a 0-5 numeric severity. Map to Faraday levels.
NUMERIC_TO_LABEL = {
    5: "critical",
    4: "high",
    3: "med",
    2: "low",
    1: "low",
    0: "info",
}

# CVSS-style fallback when the platform passes us a 0-10 score.
def _cvss_to_label(score):
    if score is None:
        return "unclassified"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unclassified"
    if s >= 9.0: return "critical"
    if s >= 7.0: return "high"
    if s >= 4.0: return "med"
    if s > 0: return "low"
    return "info"


def _parse_url(url):
    if not url:
        return {"protocol": "https", "hostname": "", "port": 443}
    url_parse = urlparse(url)
    protocol = url_parse.scheme or "https"
    hostname = url_parse.netloc
    port = url_parse.port
    if port is None:
        port = 443 if protocol == "https" else 80
    return {"protocol": protocol, "hostname": hostname, "port": port}


class SourceclearPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "sourceclear"
        self.name = "Sourceclear / Veracode SCA"
        self.plugin_version = "0.2.0"
        self.version = "0.0.2"
        self.json_keys = [
            {"metadata", "records"},      # legacy sourceclear-cli
            {"_embedded", "_links"},      # Veracode REST API HAL
            {"_embedded"},
            {"findings"},                 # platform export
        ]

    def report_belongs_to(self, file_json_keys=None, file_head="", **kwargs):
        if not super().report_belongs_to(file_json_keys=file_json_keys, **kwargs):
            return False
        if file_json_keys == {"findings"}:
            # AWS Inspector exports share the bare "findings" key
            return re.search(r'"(?:issue_id|scan_type|context_guid)"', file_head) is not None
        return True

    def parseOutputString(self, output, debug=False):
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        # Some Veracode JSON exports start with a UTF-8 BOM. Strip it.
        if output.startswith("﻿"):
            output = output.lstrip("﻿")
        data = json.loads(output)

        if isinstance(data, dict):
            if "records" in data:
                self._parse_legacy(data)
            elif "_embedded" in data:
                self._parse_embedded(data)
            elif "findings" in data:
                self._parse_findings_list(data)

    # ---- legacy sourceclear-cli ----
    def _parse_legacy(self, data):
        import os
        for record in data.get("records") or []:
            vulns = record.get("vulnerabilities") or []
            libraries = record.get("libraries") or []
            for vuln in vulns:
                v_name = vuln.get("title", "Sourceclear finding")
                v_desc = vuln.get("overview", "")
                v_links = vuln.get("_links") or {}
                v_website = v_links.get("html", "") or ""
                url_data = _parse_url(v_website)
                host_name = "unknown"
                for refs in vuln.get("libraries") or []:
                    ref = (refs.get("_links") or {}).get("ref", "")
                    num_versions = ref.find("/versions")
                    if num_versions <= 0 or not libraries:
                        continue
                    _, num_libraries = os.path.split(ref[:num_versions])
                    try:
                        idx = int(num_libraries)
                        lib = libraries[idx]
                        host_name = f"{lib.get('name','')}{lib.get('versions',[{}])[0].get('version','')}"
                    except (ValueError, IndexError, KeyError):
                        continue
                h_id = self.createAndAddHost(
                    name=host_name,
                    description=(record.get("metadata") or {}).get("recordType", ""))
                s_id = self.createAndAddServiceToHost(
                    h_id, "Sourceclear",
                    protocol=url_data["protocol"],
                    ports=url_data["port"], status="open")
                self.createAndAddVulnWebToService(
                    h_id, s_id,
                    name=v_name, desc=v_desc,
                    data=str(vuln.get("libraries") or ""),
                    website=v_website)

    # ---- Veracode HAL `_embedded.issues` ----
    def _parse_embedded(self, data):
        issues = ((data.get("_embedded") or {}).get("issues")) or \
                 ((data.get("_embedded") or {}).get("findings")) or []
        for issue in issues:
            library = issue.get("library") or {}
            vulnerability = issue.get("vulnerability") or issue
            host_label = (
                f"{library.get('name','')}@{library.get('version','')}"
            ).strip("@") or "unknown"
            host_id = self.createAndAddHost(
                host_label,
                description=f"Veracode project: {issue.get('project_name', '')}")

            severity_score = vulnerability.get("cvss3_score") or \
                             issue.get("severity")
            severity = _cvss_to_label(severity_score)

            cwe_id = vulnerability.get("cwe_id", "")
            cwe = [cwe_id] if isinstance(cwe_id, str) and cwe_id.upper().startswith("CWE-") else []
            cve = vulnerability.get("cve") or ""
            if cve and not cve.upper().startswith("CVE-"):
                cve = f"CVE-{cve}"

            cvss3 = {}
            if vulnerability.get("cvss3_vector"):
                cvss3 = {"vector_string": vulnerability["cvss3_vector"]}
                if isinstance(vulnerability.get("cvss3_score"), (int, float)):
                    cvss3["base_score"] = vulnerability["cvss3_score"]
            cvss2 = {}
            if vulnerability.get("cvss2_vector"):
                cvss2 = {"vector_string": vulnerability["cvss2_vector"]}
                if isinstance(vulnerability.get("cvss2_score"), (int, float)):
                    cvss2["base_score"] = vulnerability["cvss2_score"]

            html_url = (issue.get("_links") or {}).get("html", {}).get("href", "")
            self.createAndAddVulnToHost(
                host_id=host_id,
                name=vulnerability.get("title", "Veracode SCA finding"),
                desc=f"Detected in {host_label}\n\nCVE: {cve or 'n/a'}",
                severity=severity,
                cve=cve,
                cwe=cwe,
                cvss2=cvss2,
                cvss3=cvss3,
                ref=[html_url] if html_url else [],
                external_id=str(vulnerability.get("id") or issue.get("id") or ""),
                data=f"Library: {library.get('name','')}@{library.get('version','')}\n"
                     f"Latest: {library.get('latest_version','?')}\n"
                     f"Direct: {library.get('direct')}",
            )

    # ---- platform export `findings: [...]` ----
    def _parse_findings_list(self, data):
        for finding in data.get("findings") or []:
            details = finding.get("finding_details") or {}
            cve_data = details.get("cve") or {}
            severity_num = details.get("severity")
            severity = NUMERIC_TO_LABEL.get(int(severity_num), "unclassified") if isinstance(severity_num, (int, float)) else "unclassified"

            # Component info
            metadata = details.get("metadata") or {}
            component = details.get("component_filename") or details.get("component_id") or "unknown component"
            host_label = component
            host_id = self.createAndAddHost(
                host_label,
                description=f"Veracode {finding.get('scan_type', 'SCA')} finding")

            cwe_obj = details.get("cwe") or {}
            cwe = []
            if cwe_obj.get("id"):
                cwe.append(f"CWE-{cwe_obj['id']}")

            cve = ""
            if cve_data.get("name"):
                cve = cve_data["name"] if cve_data["name"].upper().startswith("CVE-") else f"CVE-{cve_data['name']}"
            cvss3 = {}
            if cve_data.get("cvss3"):
                v = cve_data["cvss3"]
                if v.get("vector"):
                    cvss3 = {"vector_string": v["vector"]}
                if isinstance(v.get("score"), (int, float)):
                    cvss3["base_score"] = v["score"]

            self.createAndAddVulnToHost(
                host_id=host_id,
                name=cve_data.get("name") or finding.get("description", "Veracode finding")[:80],
                desc=finding.get("description", "") or "",
                severity=severity,
                cve=cve,
                cwe=cwe,
                cvss3=cvss3,
                external_id=str(finding.get("issue_id") or finding.get("context_guid") or ""),
                data=f"Status: {(finding.get('finding_status') or {}).get('status','')}\n"
                     f"Component: {component}",
            )


def createPlugin(*args, **kwargs):
    return SourceclearPlugin(*args, **kwargs)
