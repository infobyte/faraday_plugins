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


def unescape_csv_text(value):
    """The CSV export escapes quotes JSON style on top of the CSV doubling: ``=\\""refresh\\""``.

    Cells holding a JSON array keep their escapes, they are valid there.
    """
    if not isinstance(value, str) or value.lstrip().startswith(("[", "{")):
        return value
    return value.replace('\\"', '"')


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
    """Creates hosts and vulns from ORCA findings; used by the CSV and JSON plugins."""

    def process_findings(self, findings):
        hosts = {}
        for finding in findings:
            if not isinstance(finding, dict) or not (as_text(finding.get("Name")) or as_text(finding.get("CveId"))):
                continue
            host = self.map_host(finding)
            host_id = hosts.get(host["name"])
            if host_id is None:
                host_id = self.createAndAddHost(**host)
                hosts[host["name"]] = host_id
            self.createAndAddVulnToHost(host_id=host_id, **self.map_vuln(finding))

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

    def map_host(self, finding):
        """``Inventory.Name`` identifies the cloud resource; it is kept as is, IP or not."""
        name = as_text(self.nested(finding, "Inventory", "Name")) or UNKNOWN_ASSET
        description = "\n".join(
            f"{label}: {value}" for label, value in (
                ("Cloud account", as_text(self.nested(finding, "CloudAccount", "Name"))),
                ("Business units", ", ".join(self.business_units(finding))),
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
            "severity": SEVERITY_MAP.get(as_text(finding.get("CvssSeverity")).lower(), "unclassified"),
            "ref": self.map_refs(vuln_id),
            "cve": [vuln_id.upper()] if CVE_RE.match(vuln_id) else [],
            "tags": self.map_tags(finding),
        }

    def map_resolution(self, finding, package):
        patched = as_list(finding.get("PatchedVersions"))
        package = package or "the affected package"
        if patched:
            resolution = f"Upgrade {package} to version {' or '.join(patched)} or later."
            release = as_text(finding.get("PatchReleaseDate"))
            if release:
                resolution += f" Patch released on {release}."
            return resolution
        if as_text(finding.get("PatchAvailable")).lower() == "no":
            return f"No patched version of {package} is available yet."
        return ""

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

    def map_data(self, finding):
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
                ("Cloud account", as_text(self.nested(finding, "CloudAccount", "Name"))),
            ) if value
        ]
        paths = as_list(self.nested(finding, "InstalledPackage", "NonOsPackagePaths"))
        if paths:
            lines.append("Package paths:")
            lines.extend(f"  {path}" for path in paths)
        return "\n".join(lines)
