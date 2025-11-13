import json
import re
from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.plugins_utils import filter_services


class TenableIOJSONExport(PluginJsonFormat):
    STATUS_MAP = {"ACTIVE": "open", "FIXED": "closed", "NEW": "open", "RESURFACED": "open"}
    SEVERITY_MAP = {1: "low", 2: "medium", 3: "high", 4: "critical"}
    CVSS_PREFIXES = ["", "CVSS:3.1/", "CVSS:4.0/"]
    OUTPUT_MAX_LENGTH = 10000
    WEB_SERVICES = {'http', 'https', 'www', 'http-alt', 'http-proxy', 'https-alt', 'web', 'www-http', 'ssl'}
    URL_PATTERN = re.compile(r'https?://[^\s]+', re.IGNORECASE)
    WEB_FAMILY_STRINGS = ["web", "http", "https", "ssl", "www", "cgi"]

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "tenableio_export_json"
        self.name = "Tenable IO JSON Vuln Export Plugin"
        self.plugin_version = "10.7.6"
        self.version = "1.0.0"
        self.json_keys = {'asset', 'definition', 'asset_cloud_resource', 'container_image'}
        self._temp_file_extension = "json"
        self._assets_collection = {}
        self._hostname_to_ip = {}
        self._vulns_buffer = []

    def parseOutputString(self, output):
        del self._vulns_buffer[:]
        self._assets_collection.clear()
        self._hostname_to_ip.clear()

        try:
            data = json.loads(output)  # NOSEC
        except json.JSONDecodeError:
            return

        for i, vuln in enumerate(data):
            if i % 100 == 0 and i > 0:
                self._process_batch()

            asset_info = vuln.get("asset")
            if not asset_info:
                continue

            definition = vuln.get("definition", {})
            if not definition.get("id") or not definition.get("name"):
                continue

            ipv4_list = asset_info.get("ipv4_addresses", [])
            primary_ip = ipv4_list[0] if ipv4_list else None
            host_name = asset_info.get("host_name")
            display_fqdn = asset_info.get("display_fqdn")

            hostnames = set()
            if host_name:
                hostnames.add(host_name.strip().lower())
            if display_fqdn:
                hostnames.add(display_fqdn.strip().lower())

            asset_key = primary_ip
            if not asset_key and hostnames:
                asset_key = next(iter(hostnames))

            if not asset_key:
                continue

            for hostname in hostnames:
                existing_ip = self._hostname_to_ip.get(hostname)
                if existing_ip and existing_ip != asset_key:
                    # TODO: Implement merge strategy for hostname conflicts
                    if existing_ip in self._assets_collection:
                        self._assets_collection[existing_ip]['hostnames'].update(hostnames)
                    asset_key = existing_ip
                self._hostname_to_ip[hostname] = asset_key

            if asset_key not in self._assets_collection:
                self._assets_collection[asset_key] = {
                    'hostnames': hostnames,
                    'os': asset_info.get("operating_system", "unknown"),
                    'ip': primary_ip
                }
            else:
                self._assets_collection[asset_key]['hostnames'].update(hostnames)

            self._vulns_buffer.append((asset_key, vuln))

        self._process_batch()

    def _process_batch(self):
        if not self._vulns_buffer:
            return

        created_hosts = {}
        for asset_key, asset_data in self._assets_collection.items():
            host_id = self.createAndAddHost(
                name=asset_data['ip'] or asset_key,
                os=asset_data['os'],
                hostnames=list(asset_data['hostnames'])
            )
            created_hosts[asset_key] = host_id

        for asset_key, vuln in self._vulns_buffer:
            if asset_key not in created_hosts:
                continue

            host_id = created_hosts[asset_key]
            asset_data = self._assets_collection[asset_key]
            definition = vuln.get("definition", {})
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

            refs = []
            for ref in definition.get("see_also", []):
                refs.append({"name": ref, "type": "other"})

            cvss_data = {}
            for i, version in enumerate([2, 3, 4]):
                cvss_key = f"cvss{version}"
                cvss_obj = definition.get(cvss_key)
                if cvss_obj:
                    base_vector = cvss_obj.get("base_vector", "")
                    if base_vector:
                        prefix = self.CVSS_PREFIXES[i] if i < len(self.CVSS_PREFIXES) else ""
                        cvss_data[cvss_key] = {"vector_string": f"{prefix}{base_vector}"}

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

            website = None
            if asset_data['hostnames']:
                for hostname in asset_data['hostnames']:
                    if '.' in hostname:
                        website = hostname
                        break
                if not website:
                    website = next(iter(asset_data['hostnames']))
            elif asset_data['ip']:
                website = asset_data['ip']

            if is_valid_port:
                service_name = "Unknown"
                for service in filter_services():
                    parts = service[0].split("/")
                    if len(parts) == 2 and parts[0] == str(port_int):
                        service_name = service[1]
                        break

                service_id = self.createAndAddServiceToHost(
                    host_id=host_id,
                    name=service_name,
                    protocol=protocol,
                    ports=[port_int],
                    status="open"
                )

                is_web_service = service_name.lower() in self.WEB_SERVICES
                has_url_in_data = bool(self.URL_PATTERN.search(output_content)) if output_content else False
                family = definition.get("family", "").lower()
                is_web_family = any(fam in family for fam in self.WEB_FAMILY_STRINGS)

                if is_web_service or has_url_in_data or is_web_family:
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

        self._vulns_buffer.clear()


def createPlugin(*args, **kwargs):
    return TenableIOJSONExport(*args, **kwargs)