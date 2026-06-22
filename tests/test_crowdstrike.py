"""
Test cases for Crowdstrike JSON Output Plugin
"""

import json

from unittest.mock import Mock

from faraday_plugins.plugins.repo.crowdstrike.plugin import Crowdstrike


def _base_entry(**overrides):
    entry = {
        "host_id": "host-1",
        "host_type": "server",
        "local_ip": "10.0.0.1",
        "hostname": "host-1",
        "host_tags": [],
        "os_version": "Windows",
        "cve_id": "CVE-2025-29803",
        "product": "SQL Server Management Studio",
        "severity": "High",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "references": "https://example.com",
        "cve_description": (
            "Uncontrolled search path element in Visual Studio Tools for "
            "Applications and SQL Server Management Studio allows..."
        ),
        "cvss_version": "3.1",
    }
    entry.update(overrides)
    return entry


class TestCrowdstrike:
    def setup_method(self):
        self.plugin = Crowdstrike()
        self.plugin.logger = Mock()
        self.plugin.createAndAddHost = Mock(return_value="host_id_123")
        self.plugin.createAndAddVulnToHost = Mock()

    def _name_for(self, **overrides):
        self.plugin.createAndAddVulnToHost.reset_mock()
        self.plugin.parseOutputString(json.dumps([_base_entry(**overrides)]))
        self.plugin.createAndAddVulnToHost.assert_called_once()
        return self.plugin.createAndAddVulnToHost.call_args[1]["name"]

    def test_name_combines_cve_and_product(self):
        assert self._name_for() == "CVE-2025-29803 - SQL Server Management Studio"

    def test_name_falls_back_to_cve_when_product_missing(self):
        assert self._name_for(product=None) == "CVE-2025-29803"

    def test_name_falls_back_to_product_when_cve_missing(self):
        assert self._name_for(cve_id=None) == "SQL Server Management Studio"

    def test_name_falls_back_to_truncated_description(self):
        description = _base_entry()["cve_description"]
        name = self._name_for(cve_id=None, product=None)
        assert len(name) == 50
        assert name == description[:50]

    def test_name_uses_generic_label_when_nothing_available(self):
        assert self._name_for(
            cve_id=None, product=None, cve_description=None
        ) == "Unknown vulnerability"

    def test_description_keeps_full_text(self):
        self.plugin.parseOutputString(json.dumps([_base_entry()]))
        vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
        assert vuln_call["desc"] == _base_entry()["cve_description"]
        assert vuln_call["cve"] == "CVE-2025-29803"
