"""
Faraday Penetration Test IDE
Copyright (C) 2025  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

"""

import json
import re

from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.plugins_utils import filter_services

__author__ = "Dante Acosta"
__copyright__ = "Copyright (c) 2025, Infobyte LLC"
__credits__ = ["Dante Acosta"]
__version__ = "1.0.0"
__maintainer__ = "Dante Acosta"
__email__ = "dacosta@faradaysec.com"
__status__ = "Development"


class TenableIOJSONExport(PluginJsonFormat):
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
    OUTPUT_MAX_LENGTH = 10000
    WEB_SERVICES = {'http', 'https', 'www', 'http-alt', 'http-proxy', 'https-alt', 'web', 'www-http', 'ssl'}
    URL_PATTERN = re.compile(r'https?://[^\s]+', re.IGNORECASE)
    WEB_FAMILY_STRINGS = ["web", "http", "https", "ssl", "www", "cgi"]

    def __init__(self, *arg, **kwargs) -> None:
        super().__init__(*arg, **kwargs)
        self.id = "tenableio_export_json"
        self.name = "Tenable IO JSON Vuln Export Plugin"
        self.plugin_version = "10.7.6"
        self.version = "1.0.0"
        self.json_keys = {'asset', 'definition', 'asset_cloud_resource', 'container_image'}
        self._temp_file_extension = "json"

    def detect_web_vulnerability(self, data_content: str) -> bool:
        """
        Detect if vulnerability data contains URLs indicating it's a web vulnerability.
        Returns True if http:// or https:// URLs are found in the data.
        """
        if not data_content:
            return False
        return bool(self.URL_PATTERN.search(data_content))

    def get_hostname_from_host(self, ip: str) -> str:
        for host in self.vulns_data["hosts"]:
            if ip == host.get("ip", ""):
                hostnames = host.get("hostnames", [])
                if hostnames:
                    return hostnames[0]
        return ""

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

            ipv4_list = asset_info.get("ipv4_addresses")
            display_ipv4 = ""
            if isinstance(ipv4_list, list) and len(ipv4_list) > 0:
                display_ipv4 = ipv4_list[0] if isinstance(ipv4_list[0], str) else ""

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
                hostnames=list(hostnames)
            )

            # Calculate website field once for potential use in web vulnerabilities
            website = None
            if isinstance(display_fqdn, str) and display_fqdn:
                website = display_fqdn
            elif isinstance(host_name, str) and host_name:
                website = host_name
            elif self.get_hostname_from_host(display_ipv4.strip()):
                website = self.get_hostname_from_host(display_ipv4.strip())
            elif isinstance(display_ipv4, str) and display_ipv4:
                website = display_ipv4

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
                "desc": definition.get("description", ""),
                "resolution": definition.get("solution", ""),
                "ref": refs,
                "severity": self.SEVERITY_MAP.get(vuln.get("severity", 1), "low"),
                "external_id": f"NESSUS-{definition.get('id', 'unknown')}",
                "status": self.STATUS_MAP.get(vuln.get("state", "ACTIVE"), "open"),
                "cve": definition.get("cve", []),
                "cwe": definition.get("cwe", []),
                "data": output_content
            }


            vuln_data.update(cvss_data)

            if is_valid_port:
                services_mapper = filter_services()

                service_name = "Unknown"

                for service in services_mapper:
                    _splitted_service = service[0].split("/")
                    if len(_splitted_service) != 2:
                        continue
                    _port, _protocol = _splitted_service
                    if _port == str(port_int):
                        service_name = service[1]
                        break

                self.logger.debug(f"Port {port_int} mapped to service: {service_name}")

                service_id = self.createAndAddServiceToHost(
                    host_id=host_id,
                    name=service_name,
                    protocol=protocol,
                    ports=[port_int],
                    status="open"
                )

                # Check if it's a web vulnerability by service name OR by URL detection in data
                is_web_service = service_name.lower() in self.WEB_SERVICES
                has_url_in_data = self.detect_web_vulnerability(output_content)
                # Get family for additional web vulnerability detection
                family = definition.get("family", "").lower()

                if is_web_service \
                     or has_url_in_data \
                     or any(_family_string in family for _family_string in self.WEB_FAMILY_STRINGS):
                    vuln_data["website"] = website
                    self.createAndAddVulnWebToService(
                        host_id=host_id,
                        service_id=service_id,
                        **vuln_data
                    )
                else:
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
