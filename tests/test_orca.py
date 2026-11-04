"""
Test cases for the ORCA Security CSV and JSON export plugins
"""

import csv
import io
import json
from pathlib import Path

from faraday_plugins.plugins.repo.orca_csv.plugin import OrcaCSV
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
            "Upgrade log4j-core.jar (2.14.1): org.apache.logging.log4j:log4j-core to version 2.15.0 or 2.12.2 "
            "or later. Patch released on 2021-12-10T00:00:00+00:00.")
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

    def test_missing_description_is_built_from_the_package(self):
        vuln = vulns_of(by_ip(parse_json())["10.20.30.40"])["CVE-2024-2511 - libssl1.1"]

        assert vuln["desc"] == "CVE-2024-2511 affects libssl1.1 1.1.1w-0+deb11u1."
        assert "Package type: OS package" in vuln["data"]

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

    def test_business_units_in_host_description(self):
        finding = json_finding(BusinessUnits={"count": 2, "value": [{"Name": "Payments"}, "Retail"]})

        host = parse_json(json.dumps([finding]))[0]

        assert host["description"] == "Cloud account: ACCOUNT\nBusiness units: Payments, Retail"

    def test_missing_inventory_does_not_drop_the_finding(self):
        finding = json_finding()
        del finding["Inventory"]

        hosts = parse_json(json.dumps([finding]))

        assert hosts[0]["ip"] == "0.0.0.0"
        assert len(hosts[0]["vulnerabilities"]) == 1

    def test_invalid_json_creates_nothing(self):
        assert parse_json("not json") == []
