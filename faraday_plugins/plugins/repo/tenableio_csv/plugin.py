"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

"""

import csv
import io
import sys

from faraday_plugins.plugins.plugin import PluginCSVFormat
from faraday_plugins.plugins.plugins_utils import get_severity_from_cvss

__author__ = "Gabriel Franco"
__copyright__ = "Copyright (c) 2026, Infobyte LLC"
__credits__ = ["Gabriel Franco"]
__version__ = "1.0.0"
__maintainer__ = "Gabriel Franco"
__email__ = "gabrielf@faradaysec.com"
__status__ = "Development"


class TenableIOCSVExport(PluginCSVFormat):
    """Parses the CSV vulnerability export of Tenable Vulnerability Management."""

    STATUS_MAP = {
        "active": "open",
        "new": "open",
        "resurfaced": "open",
        "fixed": "closed",
    }

    SEVERITY_MAP = {
        "none": "info",
        "info": "info",
        "informational": "info",
        "low": "low",
        "medium": "med",
        "high": "high",
        "critical": "critical",
    }

    WEB_SERVICES = {"www", "http", "https", "http-alt", "https-alt", "www-http"}

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "tenableio_csv"
        self.name = "Tenable IO CSV Vuln Export Plugin"
        self.plugin_version = "1.0.0"
        self.version = "1.0.0"
        self.framework_version = "1.0.0"
        # Columns specific to the Tenable VM export; other CSV reports do not carry them.
        self.csv_headers = {"Plugin ID", "Asset UUID", "Vulnerability State"}
        self._temp_file_extension = "csv"

    def parseOutputString(self, output, debug=False):
        csv.field_size_limit(sys.maxsize)
        reader = csv.DictReader(io.StringIO(output), delimiter=",")
        if not reader.fieldnames:
            return

        hosts = {}
        services = {}

        for row in reader:
            address = (row.get("IP Address") or row.get("Host") or "").strip()
            name = (row.get("Name") or "").strip()
            if not address or not name:
                continue

            host_id = hosts.get(address)
            if host_id is None:
                host_id = self.createAndAddHost(**self.map_host(row, address))
                hosts[address] = host_id

            vuln = self.map_vuln(host_id, row, name)

            port = self.parse_port(row.get("Port"))
            if not port:
                self.createAndAddVulnToHost(**vuln)
                continue

            protocol = (row.get("Protocol") or "tcp").strip().lower()
            service_name = (row.get("Service") or "unknown").strip().lower()
            service_key = (address, port, protocol)
            service_id = services.get(service_key)
            if service_id is None:
                service_id = self.createAndAddServiceToHost(
                    host_id, name=service_name, protocol=protocol, ports=port)
                services[service_key] = service_id

            vuln["service_id"] = service_id
            if service_name in self.WEB_SERVICES:
                vuln["website"] = (row.get("FQDN") or address).strip()
                self.createAndAddVulnWebToService(**vuln)
            else:
                self.createAndAddVulnToService(**vuln)

    @staticmethod
    def parse_port(value):
        """Tenable writes 0 for findings that are not bound to a service."""
        try:
            port = int((value or "").strip())
        except ValueError:
            return None
        return port if port > 0 else None

    @staticmethod
    def map_host(row, address):
        hostnames = []
        fqdn = (row.get("FQDN") or "").strip()
        netbios = (row.get("NetBios") or "").strip()
        if fqdn:
            hostnames.append(fqdn)
        if netbios and netbios not in hostnames:
            hostnames.append(netbios)
        return {
            "name": address,
            "hostnames": hostnames,
            "mac": (row.get("MAC Address") or "").strip(),
            "os": (row.get("OS") or "").strip(),
        }

    def map_vuln(self, host_id, row, name):
        data = (row.get("Plugin Output") or "").strip()
        vuln = {
            "host_id": host_id,
            "name": name,
            "desc": (row.get("Description") or "").strip(),
            "resolution": (row.get("Solution") or "").strip(),
            "data": data if data else "N/A",
            "external_id": (row.get("Plugin ID") or "").strip(),
            "severity": self.map_severity(row),
            "status": self.map_status(row),
            "ref": [],
            "cve": [],
            "cvss2": {},
            "cvss3": {},
        }

        see_also = (row.get("See Also") or "").strip()
        if see_also:
            vuln["ref"] = [ref.strip() for ref in see_also.splitlines() if ref.strip()]

        cve = (row.get("CVE") or "").strip()
        if cve:
            vuln["cve"] = sorted({c.strip() for c in cve.split(",") if c.strip()})

        cvss3_vector = (row.get("CVSS3 Vector") or "").strip()
        if cvss3_vector:
            if not cvss3_vector.startswith("CVSS:3."):
                cvss3_vector = f"CVSS:3.0/{cvss3_vector}"
            vuln["cvss3"]["vector_string"] = cvss3_vector

        cvss3_score = self.parse_score(row.get("CVSS3 Base Score"))
        if cvss3_score is not None:
            vuln["cvss3"]["base_score"] = cvss3_score

        cvss2_vector = (row.get("CVSS Vector") or "").strip()
        if cvss2_vector:
            vuln["cvss2"]["vector_string"] = cvss2_vector

        cvss2_score = self.parse_score(row.get("CVSS Base Score"))
        if cvss2_score is not None:
            vuln["cvss2"]["base_score"] = cvss2_score

        return vuln

    @classmethod
    def map_severity(cls, row):
        """CVSSv3 wins, then CVSSv2, then the textual Risk Factor.

        A 0.0 score is a real score meaning informational, so it is told apart
        from an empty cell rather than treated as missing.
        """
        cvss3_score = cls.parse_score(row.get("CVSS3 Base Score"))
        if cvss3_score is not None:
            return get_severity_from_cvss(cvss3_score)

        cvss2_score = cls.parse_score(row.get("CVSS Base Score"))
        if cvss2_score is not None:
            return get_severity_from_cvss(cvss2_score)

        risk_factor = (row.get("Risk Factor") or row.get("Risk") or "").strip().lower()
        return cls.SEVERITY_MAP.get(risk_factor, "unclassified")

    @classmethod
    def map_status(cls, row):
        state = (row.get("Vulnerability State") or "").strip().lower()
        return cls.STATUS_MAP.get(state, "open")

    @staticmethod
    def parse_score(value):
        value = (value or "").strip()
        if not value:
            return None
        try:
            return float(value)
        except ValueError:
            return None


def createPlugin(*args, **kwargs):
    return TenableIOCSVExport(*args, **kwargs)
