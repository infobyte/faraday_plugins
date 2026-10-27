""" Windows Defender for Endpoint plugin.

Supports three input formats:
1. NDJSON — original format, one JSON line per vuln (LastSeenTimestamp, DeviceName,
   CveId, VulnerabilitySeverityLevel, ...).
2. Microsoft Defender API single-JSON response — {"@odata.context": ..., "value": [{...}]}
   where each entry has cveId/machineId/productName/severity, etc.
3. ZIP bundle — directory layout {machines/machines.json, vulnerabilities/<name>.json}
   each containing OData responses. Machine metadata (IP, DNS name, OS) is joined
   into the per-vuln host on machineId.
"""
import json
import zipfile
from pathlib import Path

from faraday_plugins.plugins.plugin import PluginByExtension


SEVERITY_MAP = {
    "Low": "low", "Medium": "med", "High": "high", "Critical": "critical",
    "low": "low", "medium": "med", "high": "high", "critical": "critical",
    "Informational": "info", "info": "info", "Information": "info",
}


def _ndjson_records(text):
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def _odata_records(text):
    """Single-JSON Defender API response: {value: [...]} or a list."""
    obj = json.loads(text)
    if isinstance(obj, dict) and isinstance(obj.get("value"), list):
        return obj["value"]
    if isinstance(obj, list):
        return obj
    return []


class WindowsDefenderPlugin(PluginByExtension):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = "WindowsDefender_JSONL"
        self.name = "Windows Defender"
        self.plugin_version = "2.0"
        self.version = "1.0"
        self.extension = [".json", ".zip", ".jsonl"]
        self.json_keys = [
            {"LastSeenTimestamp", "SecurityUpdateAvailable"},
            {"@odata.context", "value"},
            {"cveId", "machineId", "productName"},
        ]

    def report_belongs_to(self, extension="", file_json_keys=None, **kwargs):
        if extension and extension.lower() == ".zip":
            report_path = kwargs.get("report_path", "")
            try:
                with zipfile.ZipFile(report_path) as zf:
                    names = zf.namelist()
                return (any("machines" in n for n in names) and
                        any("vulnerabilities" in n for n in names))
            except (zipfile.BadZipFile, OSError):
                return False
        if file_json_keys:
            for keyset in self.json_keys:
                if keyset.issubset(file_json_keys):
                    return True
        # Legacy NDJSON detection: the manager only fills `file_json_keys`
        # for plain JSON. For NDJSON files (one record per line) we have to
        # peek at the file ourselves and union the keys across lines.
        report_path = kwargs.get("report_path", "")
        if report_path and extension and extension.lower() in (".json", ".jsonl"):
            try:
                with open(report_path, encoding="utf-8", errors="replace") as f:
                    keys = set()
                    line_count = 0
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            return False
                        if isinstance(obj, dict):
                            keys.update(obj.keys())
                        line_count += 1
                        if line_count >= 50:
                            break
                    if line_count > 1:
                        for keyset in self.json_keys:
                            if keyset.issubset(keys):
                                return True
            except OSError:
                return False
        return False

    def _parse_filename(self, filename):
        path = Path(filename)
        if path.suffix.lower() == ".zip":
            self._parse_zip(path)
        else:
            with open(path, encoding="utf-8", errors="replace") as f:
                self.parseOutputString(f.read())

    def _parse_zip(self, zip_path):
        machines_by_id = {}
        with zipfile.ZipFile(zip_path) as zf:
            # First pass: collect machine metadata (id -> {ip, dns, os, ...}).
            for name in zf.namelist():
                if "machines" in name and name.endswith(".json"):
                    try:
                        text = zf.read(name).decode("utf-8", errors="replace")
                        data = json.loads(text)
                    except (json.JSONDecodeError, KeyError):
                        continue
                    for m in data.get("value", []) or []:
                        if m.get("id"):
                            machines_by_id[m["id"]] = m
            # Second pass: emit vulns, joining on machineId.
            for name in zf.namelist():
                if "vulnerabilities" in name and name.endswith(".json"):
                    try:
                        text = zf.read(name).decode("utf-8", errors="replace")
                    except UnicodeDecodeError:
                        continue
                    try:
                        for record in _odata_records(text):
                            self._emit_api_vuln(record, machines_by_id.get(record.get("machineId")))
                    except json.JSONDecodeError:
                        continue

    def parseOutputString(self, output):
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        stripped = output.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                records = _odata_records(output)
            except json.JSONDecodeError:
                records = []
            if records:
                for r in records:
                    self._emit_api_vuln(r, None)
                return
        # Fall back to legacy NDJSON.
        for record in _ndjson_records(output):
            self._emit_ndjson_vuln(record)

    def _emit_ndjson_vuln(self, data):
        device_name = data.pop("DeviceName", None) or data.pop("DeviceId", "Unknown")
        os_platform = data.pop("OSPlatform", "Unknown")
        cve_id = data.pop("CveId", "")
        severity_raw = data.pop("VulnerabilitySeverityLevel", "info")
        device_id = data.pop("DeviceId", "")
        software_name = data.pop("SoftwareName", "")
        software_vendor = data.pop("SoftwareVendor", "")
        data.pop("CvssScore", None)

        host_id = self.createAndAddHost(
            name=device_name,
            os=os_platform,
            hostnames=[device_name],
        )
        description = (
            f"Device Name: {device_name}\n "
            f"Device ID: {device_id}\n "
            f"OS Platform: {os_platform}\n"
            f"CVE: {cve_id}"
        )
        data_info = "\n".join(f"{k}: {v}" for k, v in data.items())
        self.createAndAddVulnToHost(
            host_id,
            name=f"{software_name}  {software_vendor} Vulnerable",
            cve=cve_id,
            severity=SEVERITY_MAP.get(severity_raw, "info"),
            desc=description,
            data=data_info,
        )

    def _emit_api_vuln(self, record, machine):
        cve = record.get("cveId") or record.get("CveId") or ""
        machine_id = record.get("machineId") or record.get("DeviceId") or ""
        product = record.get("productName") or record.get("SoftwareName") or ""
        vendor = record.get("productVendor") or record.get("SoftwareVendor") or ""
        version = record.get("productVersion") or record.get("SoftwareVersion") or ""
        severity_raw = record.get("severity") or record.get("VulnerabilitySeverityLevel") or "info"

        host_name = machine_id or "Unknown"
        ip = ""
        os_platform = "Unknown"
        if machine:
            host_name = machine.get("computerDnsName") or machine.get("id") or machine_id
            ip = machine.get("lastIpAddress") or ""
            os_platform = machine.get("osPlatform") or "Unknown"

        host_id = self.createAndAddHost(
            name=ip or host_name or "Unknown",
            os=os_platform,
            hostnames=[host_name] if host_name else [],
        )

        product_label = " ".join(filter(None, [product, vendor])).strip() or "Vulnerable software"
        if version:
            product_label = f"{product_label} ({version})"
        desc = "\n".join(filter(None, [
            f"Device: {host_name}",
            f"Machine ID: {machine_id}" if machine_id else "",
            f"Product: {product} {vendor} {version}".strip(),
            f"CVE: {cve}" if cve else "",
        ]))
        self.createAndAddVulnToHost(
            host_id,
            name=f"{product_label} vulnerable",
            cve=cve,
            severity=SEVERITY_MAP.get(severity_raw, "info"),
            desc=desc,
        )


def createPlugin(*args, **kwargs):
    return WindowsDefenderPlugin(*args, **kwargs)
