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
    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "tenableio_export_json"
        self.name = "Tenable IO JSON Vuln Export Plugin"
        self.plugin_version = "10.7.6"
        self.version = "1.0.0"
        self.json_keys = {'asset', 'definition', 'asset_cloud_resource', 'container_image'}
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return

        for vuln in data:
            # Validate asset object
            asset_info = vuln.get("asset")
            
            # Skip if asset is None or not a dictionary
            if not isinstance(asset_info, dict):
                self.logger.error(f"Omitting vulnerability {vuln.get('id', 'unknown')}: "
                                f"required field asset is missing or invalid")
                continue
            
            # Validate display_ipv4_address is present and not empty
            display_ipv4 = asset_info.get("display_ipv4_address")
            if not display_ipv4 or (isinstance(display_ipv4, str) and not display_ipv4.strip()):
                self.logger.error(f"Omitting vulnerability {vuln.get('id', 'unknown')}: "
                                f"required field asset.display_ipv4_address is missing")
                continue

            # Validate definition object - only id and name are truly required
            definition = vuln.get("definition", {})
            if not {"id", "name"}.issubset(definition.keys()):
                self.logger.error(f"Omitting vulnerability {vuln.get('id', 'unknown')}: "
                                f"definition object is missing required fields")
                continue

            # Build hostname list with priority logic
            hostnames = []
            host_name = asset_info.get("host_name")
            display_fqdn = asset_info.get("display_fqdn")
            
            if host_name:
                hostnames.append(host_name)
            if display_fqdn and display_fqdn != host_name:  # Avoid duplicates
                hostnames.append(display_fqdn)

            # Create host with display_ipv4_address as the ASSET field
            host_id = self.createAndAddHost(
                name=display_ipv4.strip(),  # ASSET field must show IP
                os=asset_info.get("operating_system", "unknown"),
                hostnames=hostnames,  # Always pass as list, even if empty
            )

            vdef = vuln.get("definition", {})

            # Process references
            refs = vdef.get("see_also", [])
            for i in range(len(refs)):
                refs[i] = {
                    "name": refs[i],
                    "type": "other"
                }

            # Status mapping
            status_map = {
                "ACTIVE": "open",
                "FIXED": "closed",
                "NEW": "open",
                "RESURFACED": "open"
            }

            # Severity mapping
            severity_map = {
                1: "low",
                2: "medium",
                3: "high",
                4: "critical"
            }

            # Process CVSS objects
            cvss_objs = [{}, {}, {}]  # for 2, 3 & 4
            for i in range(3):
                if vdef.get("cvss" + str(i + 2), None):
                    cvss_obj = vdef.get("cvss" + str(i + 2), {})
                    cvss_objs[i]["vector_string"] = (("CVSS:3.1/" if i == 1 else ("CVSS:4.0/" if i == 2 else "")) +
                                                     cvss_obj.get("base_vector", ""))

            # Process output field for Technical Details → Data
            output_content = vuln.get("output", "")
            if output_content:
                # Truncate to 10,000 characters and strip whitespace
                output_content = output_content.strip()[:10000]
            else:
                output_content = "N/A"

            # Port and service vulnerability logic
            port = vuln.get("port")
            protocol = vuln.get("protocol", "tcp").lower()  # Default to tcp if not specified
            
            # Validate port - must be integer between 1-65535
            is_valid_port = False
            port_int = None
            if port is not None:
                try:
                    port_int = int(port)
                    if 1 <= port_int <= 65535:
                        is_valid_port = True
                except (ValueError, TypeError):
                    is_valid_port = False

            # Common vulnerability data
            vuln_data = {
                "name": vdef.get("name", "Vulnerability"),
                "desc": vdef.get("description", vdef.get("solution", "No description provided.")),  # Use solution if no description
                "ref": refs,
                "severity": severity_map.get(vuln.get("severity", 1), "low"),
                "external_id": vuln.get("id", None),
                "status": status_map.get(vuln.get("state", "ACTIVE"), "open"),
                "cve": vdef.get("cve", []),
                "cvss2": cvss_objs[0],
                "cvss3": cvss_objs[1],
                "cvss4": cvss_objs[2],
                "data": output_content  # Technical Details → Data
            }

            if is_valid_port:
                # Create service vulnerability
                service_name = f"{protocol}/{port_int}"  # Use validated integer
                service_id = self.createAndAddServiceToHost(
                    host_id=host_id,
                    name=service_name,
                    protocol=protocol,
                    ports=[port_int],  # Use validated integer
                    status="open"
                )
                
                self.createAndAddVulnToService(
                    host_id=host_id,
                    service_id=service_id,
                    **vuln_data
                )
            else:
                # Create host vulnerability
                self.createAndAddVulnToHost(
                    host_id=host_id,
                    **vuln_data
                )


def createPlugin(*args, **kwargs):
    return TenableIOJSONExport(*args, **kwargs)