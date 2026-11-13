"""
Test cases for the ORCA Security CSV and JSON export plugins
"""

import csv
import io
import json
from pathlib import Path

from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer
from faraday_plugins.plugins.repo.orca_csv.plugin import OrcaCSV
from faraday_plugins.plugins.repo.orca_json.mapper import unescape_csv_text
from faraday_plugins.plugins.repo.orca_json.plugin import OrcaJson

DUMMY_FILES_FOLDER = Path.cwd() / "tests" / "data" / "orca"
CSV_REPORT = DUMMY_FILES_FOLDER / "orca_discovery_export.csv"
JSON_REPORT = DUMMY_FILES_FOLDER / "orca_discovery_export.json"

LOG4J = "CVE-2021-44228 - log4j-core.jar (2.14.1): org.apache.logging.log4j:log4j-core"


def parse(plugin, output):
    plugin.parseOutputString(output)
    return json.loads(plugin.get_json())["hosts"]


def parse_csv(output=None):
    return parse(OrcaCSV(), CSV_REPORT.read_text() if output is None else output)


def parse_json(output=None):
    return parse(OrcaJson(), JSON_REPORT.read_text() if output is None else output)


def by_ip(hosts):
    return {host["ip"]: host for host in hosts}


def vulns_of(host):
    return {vuln["name"]: vuln for vuln in host["vulnerabilities"]}


def json_finding(**overrides):
    finding = {
        "Name": "CVE-2024-0001 - pkg-1.0",
        "CveId": "CVE-2024-0001",
        "CvssSeverity": "HIGH",
        "PatchAvailable": "Yes",
        "PatchedVersions": ["1.1"],
        "HasExploit": False,
        "CisaKev": False,
        "Trending": "No",
        "CloudAccount": {"Name": "ACCOUNT"},
        "BusinessUnits": {"count": 0, "value": []},
        "Inventory": {"Name": "vm-1"},
        "InstalledPackage": {"Name": "pkg-1.0", "Version": "1.0", "IsOsPackage": False,
                             "IsInstalledByPackageManager": False},
    }
    finding.update(overrides)
    return finding


class TestOrcaDetection:

    def test_json_detected_by_keys_present_in_every_finding(self):
        keys = set(json.loads(JSON_REPORT.read_text())[0].keys())
        # The first finding of a real export may lack optional keys like ThreatImpact or Description.
        keys -= {"ThreatImpact", "Description", "CvssScore", "CvssSource", "EpssProbability"}

        assert OrcaJson().report_belongs_to(extension=".json", file_json_keys=keys)

    def test_csv_detected_by_header(self):
        headers = set(next(csv.reader(io.StringIO(CSV_REPORT.read_text()))))

        assert OrcaCSV().report_belongs_to(extension=".csv", file_csv_headers=headers)

    def test_csv_plugin_does_not_take_json(self):
        assert not OrcaCSV().report_belongs_to(extension=".json", file_csv_headers=set())

    def test_json_plugin_does_not_take_unrelated_json(self):
        assert not OrcaJson().report_belongs_to(extension=".json", file_json_keys={"Name", "Description"})


class TestOrcaBOM:
    """Exports re-saved by Excel as "CSV UTF-8" (or by other editors) start with a UTF-8 BOM"""

    @staticmethod
    def import_report(tmp_path, report):
        path = tmp_path / report.name
        path.write_bytes(b"\xef\xbb\xbf" + report.read_bytes())
        plugin = ReportAnalyzer(PluginsManager(hostname_resolution=False)).get_plugin(str(path))
        assert plugin is not None
        plugin.processReport(path)
        return plugin.id, json.loads(plugin.get_json())["hosts"]

    def test_csv_with_bom(self, tmp_path):
        plugin_id, hosts = self.import_report(tmp_path, CSV_REPORT)

        assert plugin_id == "orca_csv"
        assert hosts == parse_csv()

    def test_json_with_bom(self, tmp_path):
        plugin_id, hosts = self.import_report(tmp_path, JSON_REPORT)

        assert plugin_id == "orca_json"
        assert hosts == parse_json()


class TestOrcaParsing:

    def test_csv_and_json_exports_produce_the_same_result(self):
        assert parse_csv() == parse_json()

    def test_semicolon_separated_csv(self):
        output = io.StringIO()
        csv.writer(output, delimiter=";").writerows(csv.reader(io.StringIO(CSV_REPORT.read_text())))

        assert parse_csv(output.getvalue()) == parse_csv()

    def test_inventory_name_is_the_asset(self):
        hosts = by_ip(parse_json())

        assert set(hosts) == {"web-frontend-vm-01", "10.20.30.40", "aks-nodepool1-12345678-vmss000000",
                              "build-agent-02"}
        assert hosts["web-frontend-vm-01"]["hostnames"] == ["web-frontend-vm-01"]
        assert hosts["web-frontend-vm-01"]["description"] == "Cloud account: ACME AZURE PROD"

    def test_ip_inventory_name_is_not_a_hostname(self):
        assert by_ip(parse_json())["10.20.30.40"]["hostnames"] == []

    def test_findings_are_associated_to_their_asset(self):
        hosts = by_ip(parse_json())

        assert len(vulns_of(hosts["web-frontend-vm-01"])) == 4
        assert len(vulns_of(hosts["10.20.30.40"])) == 3
        assert LOG4J in vulns_of(hosts["web-frontend-vm-01"])
        assert LOG4J in vulns_of(hosts["build-agent-02"])
        assert hosts["build-agent-02"]["description"] == "Cloud account: ACME AZURE DEV"

    def test_vuln_mapping(self):
        vuln = vulns_of(by_ip(parse_json())["web-frontend-vm-01"])[LOG4J]

        assert vuln["severity"] == "critical"
        assert vuln["cve"] == ["CVE-2021-44228"]
        assert vuln["external_id"] == "CVE-2021-44228"
        assert vuln["desc"].startswith("Apache Log4j2 JNDI features")
        assert vuln["refs"] == [{"name": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "type": "other"}]
        assert vuln["resolution"] == (
            "Upgrade log4j-core.jar (2.14.1): org.apache.logging.log4j:log4j-core to one of the fixed versions: "
            "2.15.0, 2.12.2. Patch released on 2021-12-10T00:00:00+00:00.")
        assert set(vuln["tags"]) == {"exploit_available", "cisa_kev", "trending"}
        assert "CVSS score: 10 (NVD v3)" in vuln["data"]
        assert "Threat impact: remote_code_execution" in vuln["data"]
        assert "  /opt/app/lib/log4j-core-2.14.1.jar" in vuln["data"]

    def test_non_cve_advisories_go_to_references(self):
        hosts = by_ip(parse_json())
        ghsa = vulns_of(hosts["web-frontend-vm-01"])["GHSA-9wx4-h78v-vm56 - requests-2.31.0"]
        go = vulns_of(hosts["aks-nodepool1-12345678-vmss000000"])["GO-2024-2687 - golang.org/x/net-0.20.0"]

        assert ghsa["cve"] == []
        assert ghsa["refs"] == [{"name": "https://github.com/advisories/GHSA-9wx4-h78v-vm56", "type": "other"}]
        assert go["cve"] == []
        assert go["refs"] == [{"name": "https://pkg.go.dev/vuln/GO-2024-2687", "type": "other"}]

    def test_unknown_severity_is_unclassified(self):
        vulns = vulns_of(by_ip(parse_json())["aks-nodepool1-12345678-vmss000000"])

        assert vulns["GO-2024-2687 - golang.org/x/net-0.20.0"]["severity"] == "unclassified"

    def test_severity_falls_back_to_cvss_score(self):
        missing = json_finding(Name="missing", CvssScore=9.8)
        del missing["CvssSeverity"]
        findings = [
            missing,
            json_finding(Name="unknown", CvssSeverity="UNKNOWN", CvssScore="5.3"),
            json_finding(Name="reported", CvssSeverity="LOW", CvssScore=9.8),
            json_finding(Name="no score", CvssSeverity="UNKNOWN"),
            json_finding(Name="bad score", CvssSeverity="", CvssScore="n/a"),
            json_finding(Name="out of range", CvssSeverity="", CvssScore=11),
        ]

        vulns = vulns_of(parse_json(json.dumps(findings))[0])

        assert {name: vuln["severity"] for name, vuln in vulns.items()} == {
            "missing": "critical",
            "unknown": "med",
            "reported": "low",
            "no score": "unclassified",
            "bad score": "unclassified",
            "out of range": "unclassified",
        }

    def test_missing_description_is_built_from_the_package(self):
        vuln = vulns_of(by_ip(parse_json())["10.20.30.40"])["CVE-2024-2511 - libssl1.1"]

        assert vuln["desc"] == "CVE-2024-2511 affects libssl1.1 1.1.1w-0+deb11u1."
        assert "Package type: OS package" in vuln["data"]

    def test_single_fixed_version_or_later(self):
        vuln = vulns_of(by_ip(parse_json())["web-frontend-vm-01"])["GHSA-9wx4-h78v-vm56 - requests-2.31.0"]

        assert vuln["resolution"] == (
            "Upgrade requests-2.31.0 to version 2.32.0 or later. Patch released on 2024-05-20T00:00:00+00:00.")

    def test_without_patch(self):
        vuln = vulns_of(by_ip(parse_json())["aks-nodepool1-12345678-vmss000000"])[
            "GO-2026-0001 - golang.org/x/crypto-0.38.0"]

        assert vuln["resolution"] == "No patched version of golang.org/x/crypto-0.38.0 is available yet."
        assert "CVSS score" not in vuln["data"]

    def test_csv_backslash_escaped_quotes(self):
        """The CSV export escapes quotes as \\"" inside quoted cells"""
        vuln = vulns_of(by_ip(parse_csv())["web-frontend-vm-01"])["GHSA-9wx4-h78v-vm56 - requests-2.31.0"]

        assert '"verify=False"' in vuln["desc"]
        assert "\\" not in vuln["desc"]

    def test_unescape_csv_text(self):
        # JSON escaped text, as the export writes it: escaped quotes and backslashes are decoded.
        assert unescape_csv_text('http-equiv=\\"refresh\\"') == 'http-equiv="refresh"'
        assert unescape_csv_text('regex \\\\d+ in \\"pattern\\"') == 'regex \\d+ in "pattern"'
        assert unescape_csv_text('path \\\\\\"quoted\\"') == 'path \\"quoted"'
        # Without an escaped quote nothing is decoded: backslashes in paths are kept.
        assert unescape_csv_text("C:\\new\\dir") == "C:\\new\\dir"
        # Not a valid JSON string (unescaped quote): kept as is.
        assert unescape_csv_text('say "hi" and \\"bye\\"') == 'say "hi" and \\"bye\\"'
        # JSON array cells are left for the JSON decoding.
        assert unescape_csv_text('[\n  "a\\"b"\n]') == '[\n  "a\\"b"\n]'

    def test_business_units_in_host_description(self):
        finding = json_finding(BusinessUnits={"count": 2, "value": [{"Name": "Payments"}, "Retail"]})

        host = parse_json(json.dumps([finding]))[0]

        assert host["description"] == "Cloud account: ACCOUNT\nBusiness units: Payments, Retail"

    def test_same_resource_name_in_two_accounts(self):
        """Faraday keys hosts by name, so both resources share a host that lists every account"""
        dev = json_finding(CloudAccount={"Name": "DEV"}, BusinessUnits={"count": 1, "value": ["Retail"]},
                           InstalledPackage={"Name": "pkg-1.0", "Version": "1.0", "NonOsPackagePaths": ["/dev/pkg"]})
        prod = json_finding(CloudAccount={"Name": "PROD"}, HasExploit=True,
                            InstalledPackage={"Name": "pkg-1.0", "Version": "1.0", "NonOsPackagePaths": ["/prod/pkg"]})
        prod_only = json_finding(Name="CVE-2024-0002 - pkg-1.0", CveId="CVE-2024-0002",
                                 CloudAccount={"Name": "PROD"})

        hosts = parse_json(json.dumps([dev, prod, prod_only]))

        assert len(hosts) == 1
        assert hosts[0]["description"] == "Cloud accounts: DEV, PROD\nBusiness units: Retail"
        vulns = vulns_of(hosts[0])
        assert len(vulns) == 2
        merged = vulns["CVE-2024-0001 - pkg-1.0"]
        assert "Cloud accounts: DEV, PROD" in merged["data"]
        assert "  /dev/pkg\n  /prod/pkg" in merged["data"]
        assert merged["tags"] == ["exploit_available"]
        assert "Cloud account: PROD" in vulns["CVE-2024-0002 - pkg-1.0"]["data"]

    def test_missing_inventory_is_grouped_by_cloud_account(self):
        """Without a resource name, findings of different accounts must not end in the same host"""
        dev = json_finding(CloudAccount={"Name": "DEV"})
        prod = json_finding(CloudAccount={"Name": "PROD"})
        orphan = json_finding()
        for finding in (dev, prod, orphan):
            del finding["Inventory"]
        del orphan["CloudAccount"]

        hosts = by_ip(parse_json(json.dumps([dev, prod, orphan])))

        assert set(hosts) == {"DEV", "PROD", "0.0.0.0"}
        assert hosts["DEV"]["description"] == (
            "Note: Resource name not reported by ORCA, findings grouped by cloud account\nCloud account: DEV")
        assert hosts["0.0.0.0"]["hostnames"] == []
        assert all(len(host["vulnerabilities"]) == 1 for host in hosts.values())

    def test_unexpected_types_do_not_break_the_import(self):
        """Fields with an unexpected type fall back to their defaults instead of failing the whole report"""
        findings = [
            {"Name": 123, "CveId": None, "CvssSeverity": ["HIGH"], "Inventory": "vm-x", "InstalledPackage": None,
             "CloudAccount": "ACC"},
            {"Name": "typed", "CveId": "CVE-2024-0001", "CvssSeverity": "HIGH", "Inventory": {"Name": 42},
             "InstalledPackage": {"Name": ["pkg"], "NonOsPackagePaths": "/a,/b"}, "PatchedVersions": "1.2",
             "ThreatImpact": {"unexpected": 1}, "CvssScore": [9], "BusinessUnits": {"value": [1, None, {"Name": "BU"}]}},
            "not a finding", None, 5,
        ]

        hosts = by_ip(parse_json(json.dumps(findings)))

        assert set(hosts) == {"0.0.0.0", "42"}
        assert vulns_of(hosts["0.0.0.0"])["123"]["severity"] == "unclassified"
        typed = vulns_of(hosts["42"])["typed"]
        assert typed["severity"] == "high"
        assert "  /a\n  /b" in typed["data"]
        assert hosts["42"]["description"] == "Business units: 1, BU"

    def test_invalid_json_creates_nothing(self):
        assert parse_json("not json") == []
