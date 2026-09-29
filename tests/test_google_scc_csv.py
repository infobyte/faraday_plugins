"""
Test cases for Google Security Command Center CSV Export Plugin
"""

from pathlib import Path

from unittest.mock import Mock

from faraday_plugins.plugins.repo.google_scc_csv.plugin import GoogleSCCCSV

DUMMY_FILES_FOLDER = Path.cwd() / "tests" / "data" / "google_scc"
CSV_REPORT = DUMMY_FILES_FOLDER / "google_scc_export.csv"

THREAT_HOST = "//compute.googleapis.com/projects/example-project/global/backendServices/111"
PROJECT_HOST = "//cloudresourcemanager.googleapis.com/projects/200000000000"
CLUSTER_HOST = "//container.googleapis.com/projects/example-project/locations/us-east1/clusters/example-gke"


def read_report():
    return CSV_REPORT.read_text()


class TestGoogleSCCCSV:
    """Test suite for Google Security Command Center CSV Export Plugin"""

    def setup_method(self):
        self.plugin = GoogleSCCCSV()
        self.plugin.logger = Mock()

        self.plugin.createAndAddHost = Mock(side_effect=lambda **host: host["name"])
        self.plugin.createAndAddVulnToHost = Mock()

    def vulns(self):
        self.plugin.parseOutputString(read_report())
        return {call[1]["name"]: call[1] for call in self.plugin.createAndAddVulnToHost.call_args_list}

    # -- detection ---------------------------------------------------------

    def test_detects_semicolon_separated_header(self):
        """The analyzer splits headers on "," so the whole ";" header arrives as one column"""
        headers = {read_report().splitlines()[0]}

        assert self.plugin.report_belongs_to(extension=".csv", file_csv_headers=headers)

    def test_ignores_csv_without_scc_columns(self):
        headers = {"Host;Port;Name;Description"}

        assert not self.plugin.report_belongs_to(extension=".csv", file_csv_headers=headers)

    # -- hosts -------------------------------------------------------------

    def test_creates_one_host_per_resource(self):
        """Blank separator rows are skipped and findings on the same resource share a host"""
        self.plugin.parseOutputString(read_report())

        created = [call[1]["name"] for call in self.plugin.createAndAddHost.call_args_list]
        assert created == [THREAT_HOST, PROJECT_HOST, CLUSTER_HOST, "malicious.example.com"]

    def test_host_carries_resource_display_name_and_metadata(self):
        self.plugin.parseOutputString(read_report())

        cluster = self.plugin.createAndAddHost.call_args_list[2][1]
        assert cluster["hostnames"] == ["example-gke"]
        assert "Resource type: google.container.Cluster" in cluster["description"]
        assert "Location: us-east1" in cluster["description"]

    def test_indicator_is_host_when_finding_has_no_resource(self):
        vuln = self.vulns()["Malware: Bad Domain"]

        assert vuln["host_id"] == "malicious.example.com"

    # -- vulnerabilities ---------------------------------------------------

    def test_supports_all_finding_classes(self):
        tags = {vuln["tags"][0] for vuln in self.vulns().values()}

        assert tags == {"THREAT", "MISCONFIGURATION", "VULNERABILITY"}

    def test_category_is_vulnerability_title(self):
        assert set(self.vulns()) == {
            "Increasing Deny Ratio", "OPEN_GROUP_IAM_MEMBER", "GKE_SECURITY_BULLETIN", "Malware: Bad Domain"}

    def test_severity_mapping(self):
        severities = {name: vuln["severity"] for name, vuln in self.vulns().items()}

        assert severities == {
            "Increasing Deny Ratio": "med",
            "OPEN_GROUP_IAM_MEMBER": "low",
            "GKE_SECURITY_BULLETIN": "high",
            "Malware: Bad Domain": "critical",
        }

    def test_inactive_finding_is_closed(self):
        vulns = self.vulns()

        assert vulns["Malware: Bad Domain"]["status"] == "closed"
        assert vulns["OPEN_GROUP_IAM_MEMBER"]["status"] == "open"

    def test_references_from_external_uri_and_cve_references(self):
        vuln = self.vulns()["GKE_SECURITY_BULLETIN"]

        assert vuln["ref"] == [
            "https://console.cloud.google.com/kubernetes/security/dashboard?project=example-project",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-43284",
        ]

    def test_cve_id(self):
        vulns = self.vulns()

        assert vulns["GKE_SECURITY_BULLETIN"]["cve"] == ["CVE-2026-43284"]
        assert vulns["OPEN_GROUP_IAM_MEMBER"]["cve"] == []

    def test_description_and_resolution(self):
        vuln = self.vulns()["OPEN_GROUP_IAM_MEMBER"]

        assert vuln["desc"] == "An open group is used as an IAM policy principal."
        # No next_steps in the row, so the source_properties recommendation is used.
        assert vuln["resolution"] == "Require approval to join the group."

    def test_threat_without_description_gets_a_fallback(self):
        vuln = self.vulns()["Increasing Deny Ratio"]

        assert vuln["desc"] == "Increasing Deny Ratio reported by Cloud Armor"
        assert vuln["resolution"].startswith("1. Review your request logging")

    def test_data_keeps_indicators_and_source_properties(self):
        data = self.vulns()["Increasing Deny Ratio"]["data"]

        assert "Indicator IP addresses: 198.51.100.7" in data
        assert "Backend_Service: backend-example" in data
        assert "Long_Term_Denied_RPS: 1.0" in data

    def test_node_pool_findings_are_merged(self):
        """SCC emits one finding per node pool for the same bulletin on a cluster"""
        self.plugin.parseOutputString(read_report())

        bulletins = [call[1] for call in self.plugin.createAndAddVulnToHost.call_args_list
                     if call[1]["name"] == "GKE_SECURITY_BULLETIN"]
        assert len(bulletins) == 1
        assert "Node pools: pool-1, pool-2" in bulletins[0]["data"]
        assert "Security bulletin: GCP-2026-030-cos" in bulletins[0]["data"]

    def test_indicator_columns_accept_plain_values(self):
        row = {"finding.indicator.ip_addresses": "192.0.2.1, 192.0.2.2"}

        assert GoogleSCCCSV.parse_list(row, "finding.indicator.ip_addresses") == ["192.0.2.1", "192.0.2.2"]
