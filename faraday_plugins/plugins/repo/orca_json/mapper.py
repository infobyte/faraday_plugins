"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

Mapping shared by the ORCA Security CSV and JSON discovery export plugins.
Both exports carry the same findings: the JSON nests them (``Inventory: {Name}``)
and the CSV flattens them (``Inventory.Name``), so the CSV rows are normalized to
the JSON shape before being mapped.
"""

import ipaddress
import json
import re

from faraday_plugins.plugins.plugins_utils import get_severity_from_cvss

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

ADVISORY_URLS = (
    (CVE_RE, "https://nvd.nist.gov/vuln/detail/{}"),
    (re.compile(r"^GHSA(-[0-9a-z]{4}){3}$", re.IGNORECASE), "https://github.com/advisories/{}"),
    (re.compile(r"^GO-\d{4}-\d+$", re.IGNORECASE), "https://pkg.go.dev/vuln/{}"),
)

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "med",
    "low": "low",
    "informational": "info",
    "info": "info",
}

UNKNOWN_ASSET = "0.0.0.0"


def is_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def as_text(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()


def as_bool(value):
    return as_text(value).lower() in ("true", "yes", "1")


def as_list(value):
    """List columns come as JSON arrays in the CSV export and as real lists in the JSON one."""
    if value in (None, ""):
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return [item.strip() for item in value.split(",") if item.strip()]
    if not isinstance(value, list):
        value = [value]
    items = []
    for item in value:
        if isinstance(item, dict):
            item = item.get("Name") or item.get("name") or ""
        item = as_text(item)
        if item:
            items.append(item)
    return items


def unique(items):
    """Keeps the first occurrence order, without empty values."""
    return list(dict.fromkeys(item for item in items if item))


def unescape_csv_text(value):
    """The CSV export writes text cells JSON escaped, on top of the CSV quote doubling: ``=\\""refresh\\""``.

    Only cells showing an escaped quote are decoded, as a whole JSON string so an escaped
    backslash (``\\\\``) is decoded too; a cell that is not a valid JSON string is kept as is,
    and cells without that mark (``C:\\dir``) are never touched. JSON array cells keep
    their escapes, they are decoded later as JSON.
    """
    if not isinstance(value, str) or '\\"' not in value or value.lstrip().startswith(("[", "{")):
        return value
    try:
        return json.loads(f'"{value}"', strict=False)
    except ValueError:
        return value


def csv_row_to_finding(row):
    """Turns a flattened CSV row (``InstalledPackage.Version``) into the nested JSON finding shape.

    Columns like ``Inventory`` or ``CloudAccount`` only hold a count in the CSV and are
    replaced by the object built from their dotted columns.
    """
    row = {column: unescape_csv_text(value) for column, value in row.items()}
    finding = {}
    for column, value in row.items():
        if column is None or "." in column:
            continue
        finding[column.strip()] = value
    for column, value in row.items():
        if column is None or "." not in column:
            continue
        parent, child = column.strip().split(".", 1)
        if not isinstance(finding.get(parent), dict):
            finding[parent] = {}
        finding[parent][child] = value
    return finding


class OrcaFindingsMixin:
    """Creates hosts and vulns from ORCA findings; used by the CSV and JSON plugins.

    Faraday identifies a host only by its name (``Inventory.Name``) and a host vuln by
    its name and description, so resources sharing a name in different cloud accounts
    end up as one host, and the same finding on them as one vuln. Both are built from
    all their findings, so no account, business unit or package path is lost.
    """

    def process_findings(self, findings):
        hosts = {}
        for finding in findings:
            if not isinstance(finding, dict) or not (as_text(finding.get("Name")) or as_text(finding.get("CveId"))):
                continue
            host = hosts.setdefault(self.host_name(finding), {"findings": [], "vulns": {}})
            host["findings"].append(finding)
            vuln = self.map_vuln(finding)
            host["vulns"].setdefault((vuln["name"], vuln["desc"]), (vuln, []))[1].append(finding)

        for name, host in hosts.items():
            host_id = self.createAndAddHost(**self.map_host(name, host["findings"]))
            for vuln, vuln_findings in host["vulns"].values():
                if len(vuln_findings) > 1:
                    vuln["data"] = self.map_data(vuln_findings[0], vuln_findings)
                    vuln["tags"] = unique(tag for item in vuln_findings for tag in self.map_tags(item))
                self.createAndAddVulnToHost(host_id=host_id, **vuln)

    @staticmethod
    def nested(finding, parent, child):
        value = finding.get(parent)
        return value.get(child) if isinstance(value, dict) else None

    @classmethod
    def business_units(cls, finding):
        units = finding.get("BusinessUnits")
        if not isinstance(units, dict):
            return []
        return as_list(units.get("value", units.get("Name")))

    @classmethod
    def cloud_account(cls, finding):
        return as_text(cls.nested(finding, "CloudAccount", "Name"))

    @classmethod
    def resource_name(cls, finding):
        return as_text(cls.nested(finding, "Inventory", "Name"))

    @classmethod
    def host_name(cls, finding):
        """``Inventory.Name`` identifies the cloud resource; it is kept as is, IP or not.

        The export has no other resource identifier, so findings without it are grouped
        by cloud account to keep accounts apart, and only fall to 0.0.0.0 without both.
        """
        return cls.resource_name(finding) or cls.cloud_account(finding) or UNKNOWN_ASSET

    def map_host(self, name, findings):
        accounts = unique(self.cloud_account(finding) for finding in findings)
        units = unique(unit for finding in findings for unit in self.business_units(finding))
        unnamed = "" if any(self.resource_name(finding) for finding in findings) else \
            "Resource name not reported by ORCA, findings grouped by cloud account"
        description = "\n".join(
            f"{label}: {value}" for label, value in (
                ("Note", unnamed),
                ("Cloud accounts" if len(accounts) > 1 else "Cloud account", ", ".join(accounts)),
                ("Business units", ", ".join(units)),
            ) if value
        )
        return {
            "name": name,
            "hostnames": [] if is_ip(name) or name == UNKNOWN_ASSET else [name],
            "description": description,
        }

    def map_vuln(self, finding):
        vuln_id = as_text(finding.get("CveId"))
        package = as_text(self.nested(finding, "InstalledPackage", "Name"))
        version = as_text(self.nested(finding, "InstalledPackage", "Version"))

        desc = as_text(finding.get("Description"))
        if not desc:
            affected = f"{package} {version}" if version and version not in package else package
            desc = f"{vuln_id or 'Vulnerability'} affects {affected or 'an installed package'}."

        return {
            "name": as_text(finding.get("Name")) or f"{vuln_id} - {package}",
            "desc": desc,
            "resolution": self.map_resolution(finding, package),
            "data": self.map_data(finding),
            "external_id": vuln_id or None,
            "severity": self.map_severity(finding),
            "ref": self.map_refs(vuln_id),
            "cve": [vuln_id.upper()] if CVE_RE.match(vuln_id) else [],
            "tags": self.map_tags(finding),
        }

    @staticmethod
    def map_severity(finding):
        """``CvssSeverity`` first; when missing or UNKNOWN, derived from ``CvssScore`` if there is one."""
        severity = SEVERITY_MAP.get(as_text(finding.get("CvssSeverity")).lower())
        if severity:
            return severity
        score = as_text(finding.get("CvssScore"))
        # get_severity_from_cvss returns None for an out of range score.
        return (get_severity_from_cvss(score) if score else None) or "unclassified"

    def map_resolution(self, finding, package):
        patched = as_list(finding.get("PatchedVersions"))
        package = package or "the affected package"
        if not patched:
            if as_text(finding.get("PatchAvailable")).lower() == "no":
                return f"No patched version of {package} is available yet."
            return ""
        if len(patched) == 1:
            resolution = f"Upgrade {package} to version {patched[0]} or later."
        else:
            # Several versions usually are fixes on different branches (2.15.0 and the 2.12.2 backport),
            # so "or later" would wrongly cover versions in between, like 2.13.0.
            resolution = f"Upgrade {package} to one of the fixed versions: {', '.join(patched)}."
        release = as_text(finding.get("PatchReleaseDate"))
        if release:
            resolution += f" Patch released on {release}."
        return resolution

    @staticmethod
    def map_refs(vuln_id):
        for pattern, url in ADVISORY_URLS:
            if pattern.match(vuln_id):
                return [url.format(vuln_id)]
        return []

    def map_tags(self, finding):
        tags = []
        if as_bool(finding.get("HasExploit")):
            tags.append("exploit_available")
        if as_bool(finding.get("CisaKev")):
            tags.append("cisa_kev")
        if as_bool(finding.get("Trending")):
            tags.append("trending")
        return tags

    def map_data(self, finding, merged=None):
        """``merged`` holds every finding folded into this vuln, to list all their accounts and paths."""
        merged = merged or [finding]
        accounts = unique(self.cloud_account(item) for item in merged)
        package_type = ""
        is_os_package = self.nested(finding, "InstalledPackage", "IsOsPackage")
        if as_text(is_os_package):
            package_type = "OS package" if as_bool(is_os_package) else "Non OS package"

        cvss = as_text(finding.get("CvssScore"))
        source = as_text(finding.get("CvssSource"))
        if cvss and source:
            cvss = f"{cvss} ({source})"

        lines = [
            f"{label}: {value}" for label, value in (
                ("Package", as_text(self.nested(finding, "InstalledPackage", "Name"))),
                ("Installed version", as_text(self.nested(finding, "InstalledPackage", "Version"))),
                ("Package type", package_type),
                ("Reachability", as_text(self.nested(finding, "InstalledPackage", "ReachabilityStatus"))),
                ("CVSS score", cvss),
                ("Patch available", as_text(finding.get("PatchAvailable"))),
                ("Patched versions", ", ".join(as_list(finding.get("PatchedVersions")))),
                ("Patch release date", as_text(finding.get("PatchReleaseDate"))),
                ("Threat impact", ", ".join(as_list(finding.get("ThreatImpact")))),
                ("Exploit available", "Yes" if as_bool(finding.get("HasExploit")) else ""),
                ("CISA KEV", "Yes" if as_bool(finding.get("CisaKev")) else ""),
                ("CISA KEV due date", as_text(finding.get("CisaKevDueDate"))),
                ("EPSS probability", as_text(finding.get("EpssProbability"))),
                ("Upstream disposition", as_text(finding.get("UpstreamDisposition"))),
                ("Cloud accounts" if len(accounts) > 1 else "Cloud account", ", ".join(accounts)),
            ) if value
        ]
        paths = unique(path for item in merged
                       for path in as_list(self.nested(item, "InstalledPackage", "NonOsPackagePaths")))
        if paths:
            lines.append("Package paths:")
            lines.extend(f"  {path}" for path in paths)
        return "\n".join(lines)
