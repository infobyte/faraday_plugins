"""
Faraday Penetration Test IDE
Copyright (C) 2025  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

"""

import json

from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Dante Acosta"
__copyright__ = "Copyright (c) 2025, Infobyte LLC"
__credits__ = ["Dante Acosta"]
__version__ = "1.0.0"
__maintainer__ = "Dante Acosta"
__email__ = "dacosta@faradaysec.com"
__status__ = "Development"


class TenableIOJSONExport(PluginJsonFormat):
    # Class-level constants (created once, not per vulnerability)
    STATUS_MAP = {
        "ACTIVE": "open",
        "FIXED": "closed",
        "NEW": "open",
        "RESURFACED": "open"
    }

    SEVERITY_MAP = {
        1: "low",
        2: "medium",
        3: "high",
        4: "critical"
    }

    CVSS_PREFIXES = ["", "CVSS:3.1/", "CVSS:4.0/"]
    OUTPUT_MAX_LENGTH = 10000  # Maximum characters for output field

    def __init__(self, *arg, **kwargs) -> None:
        super().__init__(*arg, **kwargs)
        self.id = "tenableio_export_json"
        self.name = "Tenable IO JSON Vuln Export Plugin"
        self.plugin_version = "10.7.6"
        self.version = "1.0.0"
        self.json_keys = {'asset', 'definition', 'asset_cloud_resource', 'container_image'}
        self._temp_file_extension = "json"

    def parseOutputString(self, output: str) -> None:
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return

        for vuln in data:
            asset_info = vuln.get("asset")

            if not isinstance(asset_info, dict):
                self.logger.error(f"Omitting vulnerability {vuln.get('id', 'unknown')}: "
                                f"required field asset is missing or invalid")
                continue

            display_ipv4 = asset_info.get("display_ipv4_address")
            if not display_ipv4 or (isinstance(display_ipv4, str) and not display_ipv4.strip()):
                self.logger.error(f"Omitting vulnerability {vuln.get('id', 'unknown')}: "
                                f"required field asset.display_ipv4_address is missing")
                continue

            definition = vuln.get("definition", {})
            if not {"id", "name"}.issubset(definition.keys()):
                self.logger.error(f"Omitting vulnerability {vuln.get('id', 'unknown')}: "
                                f"definition object is missing required fields (id and/or name)")
                continue

            hostnames = set()
            host_name = asset_info.get("host_name")
            display_fqdn = asset_info.get("display_fqdn")

            if host_name:
                hostnames.add(host_name)
            if display_fqdn:
                hostnames.add(display_fqdn)

            host_id = self.createAndAddHost(
                name=display_ipv4.strip(),
                os=asset_info.get("operating_system", "unknown"),
                hostnames=list(hostnames),
            )

            refs = [{"name": ref, "type": "other"} for ref in definition.get("see_also", [])]

            # Build CVSS objects only when data exists
            cvss_data = {}
            for i, version in enumerate([2, 3, 4]):
                cvss_key = f"cvss{version}"
                if cvss_obj := definition.get(cvss_key):
                    base_vector = cvss_obj.get("base_vector", "")
                    if base_vector:
                        prefix = self.CVSS_PREFIXES[i] if i < len(self.CVSS_PREFIXES) else ""
                        cvss_data[cvss_key] = {"vector_string": f"{prefix}{base_vector}"}

            output_content = vuln.get("output", "")
            output_content = output_content.strip()[:self.OUTPUT_MAX_LENGTH] if output_content else "N/A"

            port = vuln.get("port")
            protocol = vuln.get("protocol", "tcp").lower()

            is_valid_port = False
            port_int = None
            if port is not None:
                try:
                    port_int = int(port)
                    is_valid_port = 1 <= port_int <= 65535
                except (ValueError, TypeError):
                    pass

            vuln_data = {
                "name": definition.get("name", "Vulnerability"),
                "desc": definition.get("description") or definition.get("solution") or "No description provided.",
                "ref": refs,
                "severity": self.SEVERITY_MAP.get(vuln.get("severity", 1), "low"),
                "external_id": vuln.get("id"),
                "status": self.STATUS_MAP.get(vuln.get("state", "ACTIVE"), "open"),
                "cve": definition.get("cve", []),
                "data": output_content
            }


            vuln_data.update(cvss_data)

            if is_valid_port:
                service_name = f"{protocol}/{port_int}"
                service_id = self.createAndAddServiceToHost(
                    host_id=host_id,
                    name=service_name,
                    protocol=protocol,
                    ports=[port_int],
                    status="open"
                )

                self.createAndAddVulnToService(
                    host_id=host_id,
                    service_id=service_id,
                    **vuln_data
                )
            else:
                self.createAndAddVulnToHost(
                    host_id=host_id,
                    **vuln_data
                )


def createPlugin(*args, **kwargs) -> TenableIOJSONExport:
    return TenableIOJSONExport(*args, **kwargs)
