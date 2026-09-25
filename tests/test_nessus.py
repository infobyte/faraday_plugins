"""
Test cases for the Nessus plugin severity mapping
"""

from pathlib import Path

import pytest

from faraday_plugins.plugins.repo.nessus.plugin import NessusPlugin

DUMMY_FILES_FOLDER = Path.cwd() / "tests" / "data" / "nessus"
NESSUS_REPORT = DUMMY_FILES_FOLDER / "nessus_cvss_severity.nessus"


@pytest.fixture
def vulns_by_name():
    plugin = NessusPlugin()
    plugin.parseOutputString(NESSUS_REPORT.read_text())

    found = {}
    for host in plugin.get_data()["hosts"]:
        for vuln in host.get("vulnerabilities", []):
            found[vuln["name"]] = vuln
        for service in host.get("services", []):
            for vuln in service.get("vulnerabilities", []):
                found[vuln["name"]] = vuln
    return found


class TestNessusSeverity:
    """A CVSSv3 score of 0.0 means Tenable assigned no v3 score, not a score of zero"""

    def test_cvss3_score_sets_the_severity(self, vulns_by_name):
        assert vulns_by_name["BlueKeep style critical"]["severity"] == "critical"
        assert vulns_by_name["MitM style medium"]["severity"] == "med"

    def test_zero_cvss3_keeps_the_reported_risk_factor(self, vulns_by_name):
        """The bug: a High finding with no CVSSv3 score imported as informational"""
        assert vulns_by_name["High with no cvss3 score"]["severity"] == "high"

    def test_zero_cvss3_keeps_the_risk_factor_for_medium(self, vulns_by_name):
        assert vulns_by_name["Medium with no cvss3 score"]["severity"] == "med"

    def test_zero_cvss3_keeps_the_risk_factor_for_low(self, vulns_by_name):
        assert vulns_by_name["Low with no cvss3 score"]["severity"] == "low"

    def test_missing_cvss3_tag_keeps_the_risk_factor(self, vulns_by_name):
        assert vulns_by_name["High with cvss3 tag absent"]["severity"] == "high"

    def test_cvss2_is_not_rated_on_cvss3_bands(self, vulns_by_name):
        """A 9.3 CVSSv2 is High, and must not be promoted to critical by the v3 bands"""
        assert vulns_by_name["High with no cvss3 score"]["severity"] == "high"
        assert vulns_by_name["High with no cvss3 score"]["cvss2"]["base_score"] == "9.3"

    def test_absent_risk_factor_uses_the_reported_severity(self, vulns_by_name):
        assert vulns_by_name["Scored finding with no risk factor"]["severity"] == "high"

    def test_no_cvss_at_all_uses_risk_factor(self, vulns_by_name):
        assert vulns_by_name["Medium with no cvss at all"]["severity"] == "med"

    def test_informational_finding_stays_info(self, vulns_by_name):
        """Nessus writes risk_factor None for informational findings, which the
        report parser turns into "0". Skipping the 0.0 CVSS score must leave that
        untouched so the finding stays informational instead of being reclassified.
        """
        assert vulns_by_name["Informational finding"]["severity"] == "info"

    def test_informational_without_cvss_stays_info(self, vulns_by_name):
        assert vulns_by_name["Informational with no cvss at all"]["severity"] == "info"

    def test_no_finding_is_dropped(self, vulns_by_name):
        assert len(vulns_by_name) == 10

    def test_reported_scores_are_kept_as_they_come(self, vulns_by_name):
        """A 0.0 score is ignored for the severity but still reported as the report has it,
        so that the stored vulnerability, and its hash, do not change."""
        vuln = vulns_by_name["High with no cvss3 score"]
        assert vuln["cvss3"]["base_score"] == "0.0"
        assert vuln["cvss2"]["base_score"] == "9.3"
