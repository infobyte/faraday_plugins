"""
Test cases for Tenable IO CSV Export Plugin
"""

from pathlib import Path

from unittest.mock import Mock

from faraday_plugins.plugins.repo.tenableio_csv.plugin import TenableIOCSVExport

DUMMY_FILES_FOLDER = Path.cwd() / "tests" / "data" / "tenableio"
CSV_REPORT = DUMMY_FILES_FOLDER / "tenableio_csv_export.csv"


def read_report():
    return CSV_REPORT.read_text()


class TestTenableIOCSVExport:
    """Test suite for Tenable IO CSV Export Plugin"""

    def setup_method(self):
        self.plugin = TenableIOCSVExport()
        self.plugin.logger = Mock()

        self.plugin.createAndAddHost = Mock(return_value="host_id_123")
        self.plugin.createAndAddServiceToHost = Mock(return_value="service_id_456")
        self.plugin.createAndAddVulnToHost = Mock()
        self.plugin.createAndAddVulnToService = Mock()
        self.plugin.createAndAddVulnWebToService = Mock()

    # -- detection ---------------------------------------------------------

    def test_detects_tenable_vm_csv_export(self):
        """The Tenable VM export columns must identify the report"""
        headers = set(read_report().splitlines()[0].split(","))

        assert self.plugin.report_belongs_to(extension=".csv", file_csv_headers=headers)

    def test_ignores_csv_without_tenable_columns(self):
        """A CSV from another tool must not be claimed by this plugin"""
        headers = {"Host", "Port", "Name", "Description"}

        assert not self.plugin.report_belongs_to(extension=".csv", file_csv_headers=headers)

    # -- hosts and services ------------------------------------------------

    def test_creates_one_host_per_asset(self):
        """Rows sharing an asset must collapse into a single host"""
        self.plugin.parseOutputString(read_report())

        created_ips = [call[1]["name"] for call in self.plugin.createAndAddHost.call_args_list]
        assert created_ips.count("192.0.2.10") == 1
        assert created_ips.count("192.0.2.11") == 1

    def test_host_carries_fqdn_and_mac(self):
        self.plugin.parseOutputString(read_report())

        first_host = self.plugin.createAndAddHost.call_args_list[0][1]
        assert first_host["hostnames"] == ["host01.example.test"]
        assert first_host["mac"] == "00:11:22:33:44:55"

    def test_creates_one_service_per_port(self):
        """Rows sharing port/protocol must reuse the same service"""
        self.plugin.parseOutputString(read_report())

        services = {
            (call[1]["ports"], call[1]["protocol"])
            for call in self.plugin.createAndAddServiceToHost.call_args_list
        }
        assert services == {(8443, "tcp"), (3389, "tcp"), (443, "tcp"), (161, "udp")}

    def test_port_zero_creates_host_vulnerability(self):
        """Port 0 means the finding is not tied to a service"""
        self.plugin.parseOutputString(read_report())

        host_vulns = [call[1]["name"] for call in self.plugin.createAndAddVulnToHost.call_args_list]
        assert host_vulns == ["Nessus Scan Information"]

    def test_web_service_creates_web_vulnerability(self):
        """www/http services get web vulns, matching the nessus plugin"""
        self.plugin.parseOutputString(read_report())

        web_vulns = [call[1]["name"] for call in self.plugin.createAndAddVulnWebToService.call_args_list]
        assert "HTTP Server Type and Version" in web_vulns
        assert "SSL Certificate Cannot Be Trusted" in web_vulns

    def test_web_vulnerability_carries_website(self):
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("HTTP Server Type and Version")
        assert vuln["website"] == "host01.example.test"

    def test_non_web_service_creates_standard_vulnerability(self):
        self.plugin.parseOutputString(read_report())

        service_vulns = [call[1]["name"] for call in self.plugin.createAndAddVulnToService.call_args_list]
        assert "RDP Server Man-in-the-Middle Weakness" in service_vulns
        assert "SNMP Agent Default Community Name" in service_vulns

    # -- severity ----------------------------------------------------------

    def test_severity_comes_from_cvss3(self):
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("RDP Server Man-in-the-Middle Weakness")
        assert vuln["severity"] == "med"

    def test_zero_cvss3_is_informational(self):
        """A 0.0 CVSS3 score must not be mistaken for an empty score"""
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("HTTP Server Type and Version")
        assert vuln["severity"] == "info"

    def test_severity_falls_back_to_cvss2(self):
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("SSL Medium Strength Cipher Suites Supported")
        assert vuln["severity"] == "med"

    def test_severity_falls_back_to_risk_factor(self):
        """With no CVSS at all the Risk Factor column decides"""
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("SNMP Agent Default Community Name")
        assert vuln["severity"] == "high"

    # -- vulnerability fields ----------------------------------------------

    def test_vuln_carries_cvss_vectors_and_scores(self):
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("RDP Server Man-in-the-Middle Weakness")
        assert vuln["cvss3"]["base_score"] == 6.5
        assert vuln["cvss3"]["vector_string"] == "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"
        assert vuln["cvss2"]["base_score"] == 5.1

    def test_vuln_carries_plugin_id_cve_and_reference(self):
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("RDP Server Man-in-the-Middle Weakness")
        assert vuln["external_id"] == "18405"
        assert vuln["cve"] == ["CVE-2005-1794"]
        assert vuln["ref"] == ["https://example.test/advisory"]

    def test_empty_cvss_is_omitted_rather_than_zeroed(self):
        """Absent CVSS must not be reported as a 0.0 score"""
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("SNMP Agent Default Community Name")
        assert vuln["cvss3"] == {}
        assert vuln["cvss2"] == {}

    # -- status ------------------------------------------------------------

    def test_active_state_maps_to_open(self):
        """Tenable writes the state in title case, not upper case"""
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("RDP Server Man-in-the-Middle Weakness")
        assert vuln["status"] == "open"

    def test_fixed_state_maps_to_closed(self):
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("SSL Certificate Cannot Be Trusted")
        assert vuln["status"] == "closed"

    def test_resurfaced_state_maps_to_open(self):
        self.plugin.parseOutputString(read_report())

        vuln = self._vuln("SNMP Agent Default Community Name")
        assert vuln["status"] == "open"

    # -- robustness --------------------------------------------------------

    def test_rows_without_address_are_skipped(self):
        """A row with no IP and no host must not create a host"""
        header = read_report().splitlines()[0]
        blank = ",".join("" for _ in header.split(","))

        self.plugin.parseOutputString(f"{header}\n{blank}\n")

        self.plugin.createAndAddHost.assert_not_called()

    def test_empty_report_is_handled(self):
        self.plugin.parseOutputString("")

        self.plugin.createAndAddHost.assert_not_called()

    # -- helpers -----------------------------------------------------------

    def _vuln(self, name):
        """Find a created vulnerability by name, web or standard"""
        calls = (self.plugin.createAndAddVulnToService.call_args_list +
                 self.plugin.createAndAddVulnWebToService.call_args_list +
                 self.plugin.createAndAddVulnToHost.call_args_list)
        for call in calls:
            if call[1]["name"] == name:
                return call[1]
        raise AssertionError(f"vulnerability {name!r} was not created")
