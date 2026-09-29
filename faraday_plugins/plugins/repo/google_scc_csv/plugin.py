"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

"""

import csv
import io
import json
import re
import sys
from urllib.parse import urlparse

from faraday_plugins.plugins.plugin import PluginCSVFormat

__author__ = "David Kraus"
__copyright__ = "Copyright (c) 2026, Infobyte LLC"
__credits__ = ["David Kraus"]
__version__ = "1.0.0"
__maintainer__ = "David Kraus"
__email__ = "dkraus@faradaysec.com"
__status__ = "Development"


class GoogleSCCCSV(PluginCSVFormat):
    """Parses the CSV findings export of Google Security Command Center."""

    DELIMITER = ";"

    SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "med",
        "low": "low",
    }

    STATUS_MAP = {
        "active": "open",
        "inactive": "closed",
    }

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "google_scc_csv"
        self.name = "Google Security Command Center CSV Export Plugin"
        self.plugin_version = "1.0.0"
        self.version = "1.0.0"
        self.framework_version = "1.0.0"
        self.csv_headers = {"finding.name", "finding.category", "finding.finding_class", "finding.resource_name"}
        self._temp_file_extension = "csv"

    def report_belongs_to(self, file_csv_headers=None, **kwargs):
        # The analyzer reads the headers with the default "," delimiter, so the
        # ";" separated header of this export arrives as a single column.
        headers = set()
        for header in file_csv_headers or set():
            headers.update(column.strip() for column in (header or "").split(self.DELIMITER))
        return super().report_belongs_to(file_csv_headers=headers, **kwargs)

    def parseOutputString(self, output, debug=False):
        csv.field_size_limit(sys.maxsize)
        reader = csv.DictReader(io.StringIO(output.lstrip("﻿")), delimiter=self.DELIMITER)
        if not reader.fieldnames:
            return

        hosts = {}
        vulns = {}
        for row in reader:
            # The export separates every finding with an empty row.
            if not self.get(row, "finding.name"):
                continue

            host = self.map_host(row)
            if host is None:
                continue
            host_id = hosts.get(host["name"])
            if host_id is None:
                host_id = self.createAndAddHost(**host)
                hosts[host["name"]] = host_id

            # SCC emits one finding per node pool for the same GKE bulletin; Faraday
            # would keep only the first, so they are merged and the pools listed.
            vuln = self.map_vuln(row)
            key = (host_id, vuln["name"], vuln["desc"])
            if key in vulns:
                vulns[key]["node_pools"].extend(
                    pool for pool in vuln["node_pools"] if pool not in vulns[key]["node_pools"])
            else:
                vulns[key] = vuln

        for (host_id, _, _), vuln in vulns.items():
            node_pools = vuln.pop("node_pools")
            if node_pools:
                vuln["data"] = "\n".join(filter(None, [vuln["data"], f"Node pools: {', '.join(node_pools)}"]))
            self.createAndAddVulnToHost(host_id=host_id, **vuln)

    @staticmethod
    def get(row, key):
        return (row.get(key) or "").strip()

    @staticmethod
    def parse_json(value, default=None):
        try:
            return json.loads(value) if value else default
        except ValueError:
            return default

    @classmethod
    def parse_list(cls, row, key):
        """Indicator columns may come as a JSON array or as plain separated values."""
        value = cls.get(row, key)
        if not value:
            return []
        parsed = cls.parse_json(value)
        if isinstance(parsed, list):
            items = parsed
        elif isinstance(parsed, str):
            items = [parsed]
        else:
            items = re.split(r"[\s,]+", value)
        return [str(item).strip() for item in items if str(item).strip()]

    @classmethod
    def source_properties(cls, row):
        properties = cls.parse_json(cls.get(row, "finding.source_properties"), [])
        if not isinstance(properties, list):
            return {}
        return {item["key"]: item.get("value") for item in properties if isinstance(item, dict) and "key" in item}

    @classmethod
    def indicators(cls, row):
        return {
            "IP addresses": cls.parse_list(row, "finding.indicator.ip_addresses"),
            "Domains": cls.parse_list(row, "finding.indicator.domains"),
            "URIs": cls.parse_list(row, "finding.indicator.uris"),
        }

    def map_host(self, row):
        """The affected GCP resource is the asset; indicators are only a fallback."""
        name = next(filter(None, (self.get(row, key) for key in (
            "finding.resource_name", "finding.cai_resource", "resource.name"))), "")
        if not name:
            indicators = self.indicators(row)
            uri_hosts = [urlparse(uri).hostname for uri in indicators["URIs"]]
            candidates = indicators["IP addresses"] + indicators["Domains"] + [h for h in uri_hosts if h]
            if not candidates:
                return None
            name = candidates[0]

        description = "\n".join(
            f"{label}: {value}" for label, value in (
                ("Resource type", self.get(row, "resource.type")),
                ("Project", self.get(row, "resource.gcp_metadata.project_display_name")),
                ("Location", self.get(row, "resource.location")),
                ("Resource path", self.get(row, "resource.resource_path_string")),
            ) if value
        )
        return {
            "name": name,
            "hostnames": [self.get(row, "resource.display_name")],
            "description": description,
        }

    def map_vuln(self, row):
        properties = self.source_properties(row)
        category = self.get(row, "finding.category")
        finding_class = self.get(row, "finding.finding_class")

        desc = self.get(row, "finding.description") or str(properties.get("Explanation") or "")
        if not desc:
            desc = f"{category} reported by {self.get(row, 'finding.parent_display_name') or 'Security Command Center'}"
        resolution = self.get(row, "finding.next_steps") or str(properties.get("Recommendation") or "")

        return {
            "name": category or self.get(row, "finding.name").rsplit("/", 1)[-1],
            "desc": desc,
            "resolution": resolution,
            "data": self.map_data(row, properties),
            "external_id": self.get(row, "finding.name"),
            "severity": self.SEVERITY_MAP.get(self.get(row, "finding.severity").lower(), "unclassified"),
            "status": self.STATUS_MAP.get(self.get(row, "finding.state").lower(), "open"),
            "ref": self.map_refs(row),
            "cve": self.map_cves(row),
            "tags": [finding_class] if finding_class else [],
            "node_pools": self.map_node_pools(row),
        }

    def map_node_pools(self, row):
        node_pools = self.parse_json(self.get(row, "finding.kubernetes.node_pools"), [])
        if not isinstance(node_pools, list):
            return []
        return [pool["name"] for pool in node_pools if isinstance(pool, dict) and pool.get("name")]

    def map_refs(self, row):
        refs = []
        external_uri = self.get(row, "finding.external_uri")
        if external_uri:
            refs.append(external_uri)
        references = self.parse_json(self.get(row, "finding.vulnerability.cve.references"), [])
        if isinstance(references, list):
            for reference in references:
                uri = reference.get("uri") if isinstance(reference, dict) else reference
                if uri and uri not in refs:
                    refs.append(str(uri))
        return refs

    def map_cves(self, row):
        cve = self.get(row, "finding.vulnerability.cve.id")
        return sorted({c.strip() for c in re.split(r"[\s,]+", cve) if c.strip()}) if cve else []

    def map_data(self, row, properties):
        lines = [
            f"{label}: {value}" for label, value in (
                ("Finding class", self.get(row, "finding.finding_class")),
                ("Source", self.get(row, "finding.parent_display_name")),
                ("Resource", self.get(row, "resource.display_name")),
                ("Resource type", self.get(row, "resource.type")),
                ("Project", self.get(row, "resource.gcp_metadata.project_display_name")),
                ("Security bulletin", self.get(row, "finding.vulnerability.security_bulletin.bulletin_id")),
                ("Suggested upgrade version",
                 self.get(row, "finding.vulnerability.security_bulletin.suggested_upgrade_version")),
                ("Event time", self.get(row, "finding.event_time")),
            ) if value
        ]
        for label, values in self.indicators(row).items():
            if values:
                lines.append(f"Indicator {label}: {', '.join(values)}")
        for key, value in properties.items():
            if key in ("Explanation", "Recommendation"):
                continue
            if not isinstance(value, str):
                value = json.dumps(value)
            lines.append(f"{key}: {value}")
        return "\n".join(lines)


def createPlugin(*args, **kwargs):
    return GoogleSCCCSV(*args, **kwargs)
