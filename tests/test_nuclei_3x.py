import pytest
from pathlib import Path
from unittest.mock import Mock
from faraday_plugins.plugins.repo.nuclei.plugin import NucleiPlugin


class TestNuclei3x:
    def test_nuclei_3x(self):
        """Test that the fixed plugin correctly parses Nuclei 3.x impact and remediation fields"""
        plugin = NucleiPlugin()
        plugin.logger = Mock()

        # Mock the creation methods to capture the calls
        plugin.createAndAddHost = Mock(return_value="host_id_123")
        plugin.createAndAddServiceToHost = Mock(return_value="service_id_456")
        plugin.createAndAddVulnWebToService = Mock()
        plugin.resolve_hostname = Mock(return_value="192.168.1.100")

        report_path = Path(__file__).parent.parent / "report-collection" / "faraday_plugins_tests" / "nuclei" / "nuclei_3_4_10.json"

        with open(report_path) as f:
            content = f.read()

        plugin.parseOutputString(content)

        # Should have created vulnerabilities
        assert plugin.createAndAddVulnWebToService.called
        vuln_calls = plugin.createAndAddVulnWebToService.call_args_list

        # Find the Log4j vulnerability call
        log4j_call = None
        for call_args in vuln_calls:
            args, kwargs = call_args
            if kwargs.get('name') and "Log4j" in kwargs['name']:
                log4j_call = kwargs
                break

        assert log4j_call is not None, "Log4j vulnerability should be created"

        # Fixed implementation should correctly get impact from Nuclei 3.x format
        impact = log4j_call.get('impact', {})
        assert impact != {}, "Fixed implementation should find impact in 3.x format"
        assert 'Impact Description' in impact, "Impact should contain descriptive text entry"

        # Fixed implementation should correctly get remediation from Nuclei 3.x format
        resolution = log4j_call.get('resolution', '')
        assert resolution != '', "Fixed implementation should find remediation in 3.x format"
        assert "Upgrade to Log4j" in resolution, "Resolution should contain remediation text"

        # CVE mapping should still work
        cve = log4j_call.get('cve')
        assert cve is not None
        assert "CVE-2021-44228" in cve

    def test_nuclei_2x_backward_compatibility(self):
        """Test that the fixed plugin still works with Nuclei 2.x format"""
        plugin = NucleiPlugin()
        plugin.logger = Mock()

        # Mock the creation methods
        plugin.createAndAddHost = Mock(return_value="host_id_123")
        plugin.createAndAddServiceToHost = Mock(return_value="service_id_456")
        plugin.createAndAddVulnWebToService = Mock()
        plugin.resolve_hostname = Mock(return_value="192.168.1.100")

        # Use existing 2.x test data
        report_path = Path(__file__).parent.parent / "report-collection" / "faraday_plugins_tests" / "nuclei" / "nuclei_2_5_3.json"

        with open(report_path) as f:
            content = f.read().split('\n')[0]  # Get first vulnerability

        plugin.parseOutputString(content)

        # Should have created vulnerabilities
        assert plugin.createAndAddVulnWebToService.called, "Should create vulnerabilities from 2.x format"

    def test_version_detection(self):
        """Test the version detection logic"""
        plugin = NucleiPlugin()

        # Test Nuclei 3.x detection
        vuln_3x = {
            "info": {
                "impact": "This is a 3.x impact field",
                "metadata": {}
            }
        }
        assert plugin._detect_nuclei_version(vuln_3x) == "3.x"

        # Test Nuclei 2.x detection
        vuln_2x = {
            "info": {
                "metadata": {
                    "impact": "tag1,tag2,tag3"
                }
            }
        }
        assert plugin._detect_nuclei_version(vuln_2x) == "2.x"
