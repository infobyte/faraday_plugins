"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from datetime import datetime

from bs4 import BeautifulSoup
from dateutil.parser import parse

from faraday_plugins.plugins.plugin import PluginJsonFormat


VULNERABILITY = "VULNERABILITY"

# ATTENTION: The following mappings are created following the common sense in order to integrate F! with SQ. You
# can see what term means in the following website: https://docs.sonarqube.org/latest/user-guide/issues/
SEVERITIES = {
    'INFO': 'unclassified',
    'MINOR': 'low',
    'MAJOR': 'medium',
    'CRITICAL': 'high',
    'BLOCKER': 'critical',
    'LOW': 'low',
    'MEDIUM': 'medium',
    'HIGH': 'high',
    'INFORMATIONAL': 'unclassified',
}
STATUSES = {
    'OPEN': 'open',
    'TO_REVIEW': 'open',
    'CONFIRMED': 'open',
    'REOPENED': 're-opened',
    'CLOSED': 'closed',
    'RESOLVED': 'closed',
    'ACKNOWLEDGED': 'open',
    'REVIEWED': 'closed',
    'SAFE': 'closed',
    'FIXED': 'closed',
}


def _safe_parse_date(value):
    if not value:
        return None
    try:
        return parse(value)
    except (ValueError, TypeError):
        return None


def _safe_html(text):
    if not text:
        return ""
    return BeautifulSoup(str(text), features="lxml").get_text(separator=" ").strip()


class SonarQubeAPIParser:
    def __init__(self, json_output):
        json_data = json.loads(json_output)
        self.vulns = self._dispatch(json_data)

    def _dispatch(self, data):
        # The /api/issues/search response has both "issues" and "components".
        # The /api/hotspots/search response has "hotspots".
        # The Generic Issue Data Provider format used by sonar-scanner CLI has
        # "issues" but no "components" and only key/severity/component/line/message.
        if "components" in data and "issues" in data:
            return self._parse_api_issues(data)
        if "hotspots" in data:
            return self._parse_api_hotspots(data)
        if "issues" in data:
            return self._parse_generic_issues(data)
        return []

    @staticmethod
    def _component_lookup(data):
        """Build component_key -> {longName, name} mapping. Tolerates missing fields."""
        out = {}
        for c in data.get("components", []) or []:
            key = c.get("key")
            if not key:
                continue
            out[key] = {
                "name": c.get("name") or key,
                "longName": c.get("longName") or c.get("path") or c.get("name") or key,
            }
        return out

    def _parse_api_issues(self, data):
        components = self._component_lookup(data)
        vulns = []
        for issue in data.get("issues", []) or []:
            if issue.get("type") and issue["type"] != VULNERABILITY:
                # Some API responses include code smells / bugs too — only take
                # things flagged as security vulnerabilities.
                continue
            component_key = issue.get("component", "")
            comp_meta = components.get(component_key, {})
            path = comp_meta.get("longName", component_key) or "unknown"
            line = issue.get("line")
            line_part = f"line {line} of " if line else ""
            data_lines = []
            for flow in issue.get("flows", []) or []:
                for location in flow.get("locations", []) or []:
                    msg = location.get("msg", "")
                    tr = location.get("textRange") or {}
                    start_line = tr.get("startLine")
                    if start_line:
                        data_lines.append(f"\"{msg}\" in line {start_line} of {path}")
                    else:
                        data_lines.append(f"\"{msg}\" in {path}")
            severity = SEVERITIES.get((issue.get("severity") or "").upper(), "unclassified")
            status = STATUSES.get((issue.get("status") or "").upper(), "open")
            vulns.append({
                "name": issue.get("message", issue.get("rule", "SonarQube finding")),
                "desc": f"Issue found in {line_part}{path}".strip(),
                "project": f"Project: {issue.get('project', '')}".strip(),
                "path": path,
                "severity": severity,
                "status": status,
                "tags": issue.get("tags") or [],
                "run_date": _safe_parse_date(issue.get("creationDate")),
                "data": "\n".join(["Flows:"] + data_lines) if data_lines else "",
                "external_id": issue.get("rule", ""),
            })
        return vulns

    def _parse_api_hotspots(self, data):
        components = self._component_lookup(data)
        vulns = []
        for hot in data.get("hotspots", []) or []:
            # In current Sonar API, hotspots embed component as a string and ruleKey
            # as a separate field. Older versions had them as nested dicts.
            comp = hot.get("component")
            if isinstance(comp, dict):
                component_key = comp.get("key", "")
                path = comp.get("longName") or comp.get("path") or component_key
            else:
                component_key = comp or ""
                path = components.get(component_key, {}).get("longName", component_key)
            project = hot.get("project")
            project_str = (project.get("key") if isinstance(project, dict) else project) or ""

            rule = hot.get("rule")
            if isinstance(rule, dict):
                # Old shape: rule has {name, vulnerabilityProbability, riskDescription, fixRecommendations}
                rule_name = rule.get("name") or hot.get("ruleKey", "Sonar hotspot")
                rule_key = rule.get("key") or hot.get("ruleKey", "")
                vp = rule.get("vulnerabilityProbability") or hot.get("vulnerabilityProbability") or "INFO"
                risk = rule.get("riskDescription") or ""
                vuln_desc = rule.get("vulnerabilityDescription") or ""
                fix = rule.get("fixRecommendations") or ""
            else:
                # New shape: ruleKey is a string at top level.
                rule_key = hot.get("ruleKey") or rule or ""
                rule_name = hot.get("message") or rule_key or "Sonar hotspot"
                vp = hot.get("vulnerabilityProbability") or "INFO"
                risk = ""
                vuln_desc = ""
                fix = ""

            severity = SEVERITIES.get(vp.upper(), "unclassified")
            data_text = "\n".join(filter(None, [
                f"Risk: {_safe_html(risk)}" if risk else "",
                f"Description: {_safe_html(vuln_desc)}" if vuln_desc else "",
            ]))
            resolution = _safe_html(fix) if fix else ""
            vulns.append({
                "name": rule_name,
                "desc": hot.get("message", "") or rule_name,
                "project": f"Project: {project_str}",
                "path": path or "unknown",
                "severity": severity,
                "status": STATUSES.get((hot.get("status") or "").upper(), "open"),
                "tags": hot.get("tags") or [],
                "run_date": _safe_parse_date(hot.get("creationDate")),
                "data": data_text,
                "external_id": rule_key,
                "resolution": resolution,
            })
        return vulns

    def _parse_generic_issues(self, data):
        """SonarQube Generic Issue Data format (sonar-scanner CLI output).

        Fields: rule, severity, status, component, line, description, message, key.
        No components map; the component string IS the path.
        """
        vulns = []
        for issue in data.get("issues", []) or []:
            path = issue.get("component", "") or "unknown"
            line = issue.get("line")
            line_part = f"Issue found in line {line} of " if line else "Issue found in "
            severity = SEVERITIES.get((issue.get("severity") or "").upper(), "unclassified")
            status = STATUSES.get((issue.get("status") or "").upper(), "open")
            vulns.append({
                "name": issue.get("message") or issue.get("rule") or "SonarQube finding",
                "desc": (issue.get("description") or f"{line_part}{path}").strip(),
                "project": "",
                "path": path,
                "severity": severity,
                "status": status,
                "tags": [],
                "run_date": _safe_parse_date(issue.get("creationDate")),
                "data": "",
                "external_id": issue.get("rule", "") or issue.get("key", ""),
            })
        return vulns


class SonarQubeAPIPlugin(PluginJsonFormat):
    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        # Multiple alternative key sets so the auto-detector picks us up across
        # the different flavors of Sonar JSON we now support.
        self.json_keys = [
            {"issues", "components", "paging"},
            {"issues", "components", "facets"},
            {"hotspots", "components"},
            {"issues", "allBugs"},
            {"issues", "hotspotKeys"},
        ]
        self.id = "sonarqubeAPI"
        self.name = "SonarQube API Plugin"
        self.plugin_version = "0.1.0"

    def parseOutputString(self, output, debug=False):
        parser = SonarQubeAPIParser(output)
        for vuln in parser.vulns:
            project = vuln.pop("project", "") or ""
            host_id = self.createAndAddHost(vuln.pop("path"), description=project)
            self.createAndAddVulnToHost(
                host_id=host_id,
                **vuln,
            )


def createPlugin(*args, **kwargs):
    return SonarQubeAPIPlugin(*args, **kwargs)
