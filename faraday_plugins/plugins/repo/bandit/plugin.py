import json
import re
import xml.etree.ElementTree as ET

from faraday_plugins.plugins.plugin import PluginXMLFormat


SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "med",
    "LOW": "low",
    "UNDEFINED": "info",
    "ERROR": "high",
    "WARNING": "med",
}


class BanditPlugin(PluginXMLFormat):
    """Parses Bandit reports.

    Supports the original junit-style XML (``bandit -f xml``) and the JSON
    output (``bandit -f json``) — Bandit emits both shapes and the JSON one is
    the default in current versions.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "testsuite"
        self.extension = [".xml", ".json"]
        self.id = "Bandit"
        self.name = "Bandit Output Plugin"
        self.plugin_version = "0.0.2"

    def report_belongs_to(self, main_tag="", file_json_keys=None, **kwargs):
        # XML branch — keep the original "testsuite name=bandit" sniff.
        if main_tag == self.identifier_tag:
            report_path = kwargs.get("report_path", "")
            try:
                with open(report_path) as f:
                    output = f.read()
                return re.search('testsuite name="bandit"', output) is not None
            except OSError:
                return False
        # JSON branch — Bandit JSON has these top-level fields.
        if file_json_keys:
            return {"results", "metrics", "generated_at"}.issubset(file_json_keys)
        return False

    def parseOutputString(self, output):
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        stripped = output.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            self._parse_json(output)
        else:
            self._parse_xml(output)
        return True

    def _parse_xml(self, output):
        tree = ET.fromstring(output)
        for testcase in tree.findall("testcase"):
            error = testcase.find("error")
            if error is None:
                continue
            name = testcase.attrib.get("name", "")
            path = testcase.attrib.get("classname", "")
            severity = SEVERITY_MAP.get((error.attrib.get("type") or "").upper(),
                                        error.attrib.get("type", "info"))
            issue_text = error.text or ""
            more_info = error.attrib.get("more_info", "")
            host_id = self.createAndAddHost(path or "unknown")
            self.createAndAddVulnToHost(
                host_id=host_id,
                name=name,
                desc=issue_text,
                ref=[more_info] if more_info else [],
                severity=severity,
            )

    def _parse_json(self, output):
        data = json.loads(output)
        results = data.get("results", []) or []
        for r in results:
            filename = r.get("filename") or "unknown"
            host_id = self.createAndAddHost(filename)
            sev_raw = (r.get("issue_severity") or "").upper()
            severity = SEVERITY_MAP.get(sev_raw, "info")
            test_id = r.get("test_id", "")
            test_name = r.get("test_name", "") or r.get("issue_text", "")[:60]
            name = f"{test_id} {test_name}".strip() if test_id else test_name
            line = r.get("line_number")
            data_lines = []
            if line:
                data_lines.append(f"Line {line}")
            code = r.get("code")
            if code:
                data_lines.append(code)
            refs = []
            if r.get("more_info"):
                refs.append(r["more_info"])
            cwe_id = (r.get("issue_cwe") or {}).get("id")
            cwe = [f"CWE-{cwe_id}"] if cwe_id else []
            self.createAndAddVulnToHost(
                host_id=host_id,
                name=name or "Bandit finding",
                desc=r.get("issue_text", ""),
                data="\n".join(data_lines),
                ref=refs,
                severity=severity,
                external_id=test_id,
                cwe=cwe,
            )


def createPlugin(*args, **kwargs):
    return BanditPlugin(*args, **kwargs)
