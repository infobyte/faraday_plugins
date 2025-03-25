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
            if not {"id", "name"}.issubset(vuln.get("asset", {}).keys()):
                continue

            if not {"id", "name", "description"}.issubset(vuln.get("definition", {}).keys()):
                continue

            asset_info = vuln.get("asset", {})

            host = self.createAndAddHost(
                name=next((asset_info.get(field) for field in ["name", "netbios_name", "id"] if
                           asset_info.get(field) is not None), "unknown"),
                os=asset_info.get("operating_system", "unknown"),
                hostnames=asset_info.get("host_name", None),
            )

            vdef = vuln.get("definition", {})

            refs = vdef.get("see_also", [])
            for i in range(len(refs)):
                refs[i] = {
                    "name": refs[i],
                    "type": "other"
                }

            status_map = {
                "ACTIVE": "open",
                "FIXED": "closed",
                "NEW": "open",
                "RESURFACED": "open"
            }

            severity_map = {
                1: "low",
                2: "medium",
                3: "high",
                4: "critical"
            }

            cvss_objs = [{}, {}, {}]  # for 2, 3 & 4
            for i in range(3):
                if vdef.get("cvss"+str(i+2), None):
                    cvss_obj = vdef.get("cvss"+str(i+2), {})
                    cvss_objs[i]["vector_string"] = (("CVSS:3.1/" if i == 1 else ("CVSS:4.0/" if i == 2 else "")) +
                                                     cvss_obj.get("base_vector", ""))

            print(cvss_objs)
            self.createAndAddVulnToHost(
                host_id=host,
                name=vdef.get("name", "Vulnerability"),
                desc=vdef.get("description", "No description provided."),
                ref=refs,
                severity=severity_map.get(vuln.get("severity", 1), "low"),
                external_id=vuln.get("id", None),
                status=status_map.get(vuln.get("state", "ACTIVE"), "open"),
                cve=vdef.get("cve", []),
                cvss2=cvss_objs[0],
                cvss3=cvss_objs[1],
                cvss4=cvss_objs[2]
            )


def createPlugin(*args, **kwargs):
    return TenableIOJSONExport(*args, **kwargs)
