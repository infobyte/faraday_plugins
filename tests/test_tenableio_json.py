"""
Test cases for Tenable IO JSON Export Plugin
"""

import json
import os
from pathlib import Path

import pytest
from unittest.mock import Mock, patch, MagicMock
from faraday_plugins.plugins.repo.tenableio_export_json.plugin import TenableIOJSONExport

DUMMY_FILES_FOLDER = Path.cwd() / "tests" / "data" / "tenableio"

class TestTenableIOJSONExport:
    """Test suite for Tenable IO JSON Export Plugin"""

    def setup_method(self):
        """Setup test environment before each test"""
        self.plugin = TenableIOJSONExport()
        self.plugin.logger = Mock()

        self.plugin.createAndAddHost = Mock(return_value=("host_id_123", {"hostnames": []}))
        self.plugin.createAndAddServiceToHost = Mock(return_value="service_id_456")
        self.plugin.createAndAddVulnToHost = Mock()
        self.plugin.createAndAddVulnToService = Mock()
        self.plugin.createAndAddVulnWebToService = Mock()


    def test_vulnerability_without_port(self):
        """Test parsing vulnerability without port (should create host vulnerability)"""
        test_data = [{
            "id": "vuln_002",
            "asset": {
                "ipv4_addresses": ["10.0.0.50"],
                "host_name": "desktop01"
            },
            "definition": {
                "id": 67890,
                "name": "Windows Update Missing",
                "description": "Critical Windows updates are missing"
            },
            "severity": 4,
            "state": "NEW"
        }]

        self.plugin.parseOutputString(json.dumps(test_data))

        # Verify host vulnerability creation (not service vulnerability)
        self.plugin.createAndAddVulnToHost.assert_called_once()
        self.plugin.createAndAddVulnToService.assert_not_called()

        # Verify data field is "N/A" when output is missing
        vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
        assert vuln_call["data"] == "N/A"
        assert vuln_call["severity"] == "critical"

    def test_invalid_port_creates_host_vulnerability(self):
        """Test that invalid port values create host vulnerabilities"""
        test_cases = [
            {"port": 0, "desc": "port is 0"},
            {"port": -1, "desc": "port is negative"},
            {"port": 70000, "desc": "port exceeds 65535"},
            {"port": "invalid", "desc": "port is string"},
            {"port": None, "desc": "port is None"},
            {"desc": "port field missing"}  # No port field
        ]

        for test_case in test_cases:
            self.plugin.createAndAddVulnToHost.reset_mock()
            self.plugin.createAndAddVulnToService.reset_mock()

            vuln_data = {
                "id": f"vuln_{test_case.get('desc', 'no_port')}",
                "asset": {
                    "ipv4_addresses": ["172.16.0.1"]
                },
                "definition": {
                    "id": 111,
                    "name": "Test Vulnerability",
                    "description": f"Testing {test_case['desc']}"
                }
            }

            if "port" in test_case:
                vuln_data["port"] = test_case["port"]

            self.plugin.parseOutputString(json.dumps([vuln_data]))

            # Should create host vulnerability, not service
            self.plugin.createAndAddVulnToHost.assert_called_once()
            self.plugin.createAndAddVulnToService.assert_not_called()

    def test_asset_validation_failures(self):
        """Test that invalid asset objects are properly skipped with error logging"""
        test_cases = [
            {
                "data": {"id": "test1", "asset": None},
                "error_msg": "Omitting vulnerability test1: required field asset is missing or invalid"
            },
            {
                "data": {"id": "test5", "asset": "not_a_dict"},
                "error_msg": "Omitting vulnerability test5: required field asset is missing or invalid"
            }
        ]

        for test_case in test_cases:
            self.plugin.logger.error.reset_mock()
            self.plugin.createAndAddHost.reset_mock()

            # Add required definition to avoid other validation errors
            test_case["data"]["definition"] = {
                "id": 1, "name": "Test", "description": "Test"
            }

            self.plugin.parseOutputString(json.dumps([test_case["data"]]))

            # Verify error was logged
            self.plugin.logger.error.assert_called_once_with(test_case["error_msg"])

            # Verify no host was created
            self.plugin.createAndAddHost.assert_not_called()

    def test_hostname_priority_logic(self):
        """Test hostname priority: host_name > display_fqdn > empty"""
        test_cases = [
            {
                "asset": {
                    "ipv4_addresses": ["192.168.1.1"],
                    "host_name": "server01",
                    "display_fqdn": "server01.domain.com"
                },
                "expected_hostnames": ["server01", "server01.domain.com"]
            },
            {
                "asset": {
                    "ipv4_addresses": ["192.168.1.2"],
                    "display_fqdn": "server02.domain.com"
                },
                "expected_hostnames": ["server02.domain.com"]
            },
            {
                "asset": {
                    "ipv4_addresses": ["192.168.1.3"],
                    "host_name": "server03"
                },
                "expected_hostnames": ["server03"]
            },
            {
                "asset": {
                    "ipv4_addresses": ["192.168.1.4"]
                },
                "expected_hostnames": []  # No hostnames - empty list
            }
        ]

        for test_case in test_cases:
            self.plugin.createAndAddHost.reset_mock()

            vuln_data = {
                "id": "test_hostname",
                "asset": test_case["asset"],
                "definition": {"id": 1, "name": "Test", "description": "Test"}
            }

            self.plugin.parseOutputString(json.dumps([vuln_data]))

            # Verify hostname parameter
            call_args = self.plugin.createAndAddHost.call_args[1]
            # Since we use a set, order might change but content should be same
            assert set(call_args["hostnames"]) == set(test_case["expected_hostnames"])

    def test_output_field_processing(self):
        """Test output field truncation and whitespace handling"""
        # Test with long output (should be truncated to 10,000 chars)
        long_output = "A" * 15000
        test_data = [{
            "id": "test_output",
            "asset": {"ipv4_addresses": ["10.0.0.1"]},
            "definition": {"id": 1, "name": "Test", "description": "Test"},
            "output": f"  {long_output}  "  # With leading/trailing whitespace
        }]

        self.plugin.parseOutputString(json.dumps(test_data))

        vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
        # Should be stripped and truncated
        assert vuln_call["data"] == "A" * 10000
        assert len(vuln_call["data"]) == 10000

    def test_output_preserves_internal_formatting(self):
        """Test that internal formatting (newlines, etc.) is preserved"""
        test_output = "Line 1\n\tIndented line 2\n  Spaced line 3"
        test_data = [{
            "id": "test_formatting",
            "asset": {"ipv4_addresses": ["10.0.0.2"]},
            "definition": {"id": 1, "name": "Test", "description": "Test"},
            "output": f"  {test_output}  "  # With external whitespace
        }]

        self.plugin.parseOutputString(json.dumps(test_data))

        vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
        # Internal formatting preserved, external whitespace stripped
        assert vuln_call["data"] == test_output


    def test_state_mapping(self):
        """Test vulnerability state mapping"""
        state_tests = [
            ("ACTIVE", "open"),
            ("FIXED", "closed"),
            ("NEW", "open"),
            ("RESURFACED", "open"),
            ("UNKNOWN", "open")  # Default case
        ]

        for input_state, expected_status in state_tests:
            self.plugin.createAndAddVulnToHost.reset_mock()

            test_data = [{
                "id": f"test_state_{input_state}",
                "asset": {"ipv4_addresses": ["10.0.0.4"]},
                "definition": {"id": 1, "name": "Test", "description": "Test"},
                "state": input_state
            }]

            self.plugin.parseOutputString(json.dumps(test_data))

            vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
            assert vuln_call["status"] == expected_status

    def test_severity_mapping(self):
        """Test severity level mapping"""
        severity_tests = [
            (1, "low"),
            (2, "medium"),
            (3, "high"),
            (4, "critical"),
            (5, "low"),  # Unknown severity defaults to low
            (None, "low")  # Missing severity defaults to low
        ]

        for input_severity, expected_severity in severity_tests:
            self.plugin.createAndAddVulnToHost.reset_mock()

            test_data = [{
                "id": f"test_severity_{input_severity}",
                "asset": {"ipv4_addresses": ["10.0.0.5"]},
                "definition": {"id": 1, "name": "Test", "description": "Test"}
            }]

            if input_severity is not None:
                test_data[0]["severity"] = input_severity

            self.plugin.parseOutputString(json.dumps(test_data))

            vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
            assert vuln_call["severity"] == expected_severity


    def test_json_decode_error(self):
        """Test handling of invalid JSON input (covers lines 34-35)"""
        invalid_json = "{ this is not valid json }"

        # Should handle gracefully without raising exception
        self.plugin.parseOutputString(invalid_json)

        # Should not create any hosts or vulnerabilities
        self.plugin.createAndAddHost.assert_not_called()
        self.plugin.createAndAddVulnToHost.assert_not_called()
        self.plugin.createAndAddVulnToService.assert_not_called()

    def test_missing_definition_fields(self):
        """Test handling of missing required definition fields (covers lines 56-58)"""
        test_data = [{
            "id": "vuln_missing_def",
            "asset": {
                "ipv4_addresses": ["192.168.1.100"],
                "host_name": "test-host"
            },
            "definition": {
                "id": 12345,
                # Missing 'name' field (required)
            }
        }]

        self.plugin.parseOutputString(json.dumps(test_data))

        # Should log error and skip this vulnerability
        self.plugin.logger.error.assert_called_with(
            "Omitting vulnerability vuln_missing_def: definition object is missing required fields (id and/or name)"
        )
        self.plugin.createAndAddHost.assert_not_called()

    def test_cvss_vectors_present(self):
        """Test CVSS vector processing when CVSS data exists (covers lines 107-108)"""
        test_data = [{
            "id": "vuln_with_cvss",
            "asset": {
                "ipv4_addresses": ["192.168.1.100"]
            },
            "definition": {
                "id": 12345,
                "name": "CVSS Test Vulnerability",
                "description": "Testing CVSS processing",
                "cvss2": {
                    "base_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N"
                },
                "cvss3": {
                    "base_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                },
                "cvss4": {
                    "base_vector": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N"
                }
            },
            "severity": 2
        }]

        self.plugin.parseOutputString(json.dumps(test_data))

        # Verify CVSS data is properly formatted
        vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
        # Now only CVSS fields with data are included
        assert "cvss2" in vuln_call
        assert "cvss3" in vuln_call
        assert "cvss4" in vuln_call
        assert vuln_call["cvss2"]["vector_string"] == "AV:N/AC:L/Au:N/C:P/I:N/A:N"
        assert vuln_call["cvss3"]["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        assert vuln_call["cvss4"]["vector_string"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N"

    def test_missing_description_uses_empty_string(self):
        """Test that when description is missing, empty string is used"""
        test_data = [{
            "id": "vuln_no_desc",
            "asset": {
                "ipv4_addresses": ["192.168.1.100"]
            },
            "definition": {
                "id": 12345,
                "name": "Test Vulnerability",
                "solution": "Apply the latest security patches"
            },
            "severity": 2
        }]

        self.plugin.parseOutputString(json.dumps(test_data))

        vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
        assert vuln_call["desc"] == ""
        assert vuln_call["resolution"] == "Apply the latest security patches"

    def test_external_id_format(self):
        """Test that external_id is properly formatted with NESSUS- prefix using definition.id"""
        test_cases = [
            (123, "NESSUS-123"),
            (456, "NESSUS-456"),
            (12345, "NESSUS-12345"),
            ("plugin-id-789", "NESSUS-plugin-id-789"),
        ]

        for definition_id, expected_external_id in test_cases:
            self.plugin.createAndAddVulnToHost.reset_mock()

            test_data = [{
                "id": "vuln_instance_id",
                "asset": {
                    "ipv4_addresses": ["192.168.1.100"]
                },
                "definition": {
                    "id": definition_id,
                    "name": "Test Vulnerability",
                    "description": "Test description"
                }
            }]

            self.plugin.parseOutputString(json.dumps(test_data))

            vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
            assert vuln_call["external_id"] == expected_external_id

    def test_service_mapping_real_filter_services(self):
        """Test service mapping with actual filter_services() without mocking"""
        from faraday_plugins.plugins.plugins_utils import filter_services

        services_map = filter_services()

        well_known_ports = [
            (21, 'ftp'),
            (22, 'ssh'),
            (23, 'telnet'),
            (25, 'smtp'),
            (53, 'domain'),
            (80, 'http'),
            (110, 'pop3'),
            (143, 'imap2'),
            (443, 'https'),
            (3306, 'mysql'),
            (5432, 'postgresql'),
            (8080, 'http-alt')
        ]

        for port, expected_service in well_known_ports:
            self.plugin.createAndAddServiceToHost.reset_mock()

            test_data = [{
                "id": f"test_real_port_{port}",
                "asset": {"ipv4_addresses": ["10.0.0.1"]},
                "definition": {"id": 1, "name": "Test Vuln", "description": "Test"},
                "port": port
            }]

            self.plugin.parseOutputString(json.dumps(test_data))

            call_args = self.plugin.createAndAddServiceToHost.call_args[1]
            assert call_args["name"] == expected_service
            assert call_args["ports"] == [port]

        self.plugin.createAndAddServiceToHost.reset_mock()
        unmapped_port = 54321
        test_data = [{
            "id": "test_unmapped_port",
            "asset": {"ipv4_addresses": ["10.0.0.1"]},
            "definition": {"id": 1, "name": "Test Vuln", "description": "Test"},
            "port": unmapped_port
        }]

        self.plugin.parseOutputString(json.dumps(test_data))

        call_args = self.plugin.createAndAddServiceToHost.call_args[1]
        assert call_args["name"] == "Unknown"
        assert call_args["ports"] == [unmapped_port]

    def test_ipv4_addresses_list_first_element(self):
        """Test that the first IP from ipv4_addresses list is used as host name"""
        test_cases = [
            {
                "ipv4_addresses": ["192.168.1.100"],
                "expected_ip": "192.168.1.100",
                "desc": "single IP in list"
            },
            {
                "ipv4_addresses": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                "expected_ip": "10.0.0.1",
                "desc": "multiple IPs - should use first"
            },
            {
                "ipv4_addresses": ["172.16.50.100", "192.168.1.1"],
                "expected_ip": "172.16.50.100",
                "desc": "two IPs - should use first"
            },
        ]

        for test_case in test_cases:
            self.plugin.createAndAddHost.reset_mock()

            test_data = [{
                "id": f"test_{test_case['desc']}",
                "asset": {
                    "ipv4_addresses": test_case["ipv4_addresses"],
                    "host_name": "testhost"
                },
                "definition": {"id": 1, "name": "Test", "description": "Test"}
            }]

            self.plugin.parseOutputString(json.dumps(test_data))

            call_args = self.plugin.createAndAddHost.call_args[1]
            assert call_args["name"] == test_case["expected_ip"]

    def test_ipv4_addresses_empty_or_invalid(self):
        """Test handling of empty or invalid ipv4_addresses field"""
        test_cases = [
            {
                "asset": {"ipv4_addresses": []},
                "desc": "empty list"
            },
            {
                "asset": {"ipv4_addresses": None},
                "desc": "None value"
            },
            {
                "asset": {"ipv4_addresses": "not_a_list"},
                "desc": "string instead of list"
            },
            {
                "asset": {"host_name": "testhost"},
                "desc": "missing ipv4_addresses field"
            },
        ]

        for test_case in test_cases:
            self.plugin.createAndAddHost.reset_mock()

            test_data = [{
                "id": f"test_{test_case['desc']}",
                "asset": test_case["asset"],
                "definition": {"id": 1, "name": "Test", "description": "Test"}
            }]

            self.plugin.parseOutputString(json.dumps(test_data))

            call_args = self.plugin.createAndAddHost.call_args[1]
            assert call_args["name"] == ""

    def test_web_service_creates_web_vulnerability(self):
        """Test that web services (http, https) create VulnerabilityWeb instead of regular Vulnerability"""

        web_service_tests = [
            (80, 'http', 'webserver.example.com'),
            (443, 'https', 'secure.example.com'),
            (8080, 'http-proxy', 'proxy.example.com'),
        ]

        for port, expected_service, fqdn in web_service_tests:
            self.plugin.createAndAddVulnWebToService.reset_mock()
            self.plugin.createAndAddVulnToService.reset_mock()

            test_data = [{
                "id": f"vuln_web_{port}",
                "asset": {
                    "ipv4_addresses": ["192.168.1.10"],
                    "display_fqdn": fqdn,
                },
                "definition": {
                    "id": 12345,
                    "name": "Web Vulnerability",
                    "description": "A web-related vulnerability"
                },
                "port": port,
                "protocol": "TCP"
            }]

            self.plugin.parseOutputString(json.dumps(test_data))

            self.plugin.createAndAddVulnWebToService.assert_called_once()
            self.plugin.createAndAddVulnToService.assert_not_called()

            vuln_call = self.plugin.createAndAddVulnWebToService.call_args[1]
            assert vuln_call["website"] == fqdn
            assert vuln_call["name"] == "Web Vulnerability"

    @patch('faraday_plugins.plugins.repo.tenableio_export_json.plugin.filter_services')
    def test_non_web_service_creates_regular_vulnerability(self, mock_filter_services):
        """Test that non-web services create regular Vulnerability, not VulnerabilityWeb"""
        mock_filter_services.return_value = [
            ('22', 'ssh'),
            ('3306', 'mysql'),
            ('5432', 'postgresql'),
        ]

        non_web_service_tests = [
            (22, 'ssh'),
            (3306, 'mysql'),
            (5432, 'postgresql'),
        ]

        for port, expected_service in non_web_service_tests:
            self.plugin.createAndAddVulnWebToService.reset_mock()
            self.plugin.createAndAddVulnToService.reset_mock()

            test_data = [{
                "id": f"vuln_non_web_{port}",
                "asset": {
                    "ipv4_addresses": ["192.168.1.20"],
                    "display_fqdn": "database.example.com",
                },
                "definition": {
                    "id": 54321,
                    "name": "Non-Web Vulnerability",
                    "description": "A non-web vulnerability"
                },
                "port": port,
                "protocol": "TCP"
            }]

            self.plugin.parseOutputString(json.dumps(test_data))

            self.plugin.createAndAddVulnToService.assert_called_once()
            self.plugin.createAndAddVulnWebToService.assert_not_called()

            vuln_call = self.plugin.createAndAddVulnToService.call_args[1]
            assert vuln_call["name"] == "Non-Web Vulnerability"
            assert "website" not in vuln_call

    def test_web_service_without_fqdn_uses_ip(self):
        """Test that web services without FQDN fall back to IP for website field"""

        test_data = [{
            "id": "vuln_web_no_fqdn",
            "asset": {
                "ipv4_addresses": ["10.0.0.50"],
            },
            "definition": {
                "id": 99999,
                "name": "Web Vuln No FQDN",
                "description": "Test"
            },
            "port": 80,
            "protocol": "TCP"
        }]

        self.plugin.parseOutputString(json.dumps(test_data))

        self.plugin.createAndAddVulnWebToService.assert_called_once()
        vuln_call = self.plugin.createAndAddVulnWebToService.call_args[1]
        assert vuln_call["website"] == "10.0.0.50"

    def test_website_field_priority(self):
        """Test website field priority: display_fqdn > host_name > display_ipv4"""

        # Test 1: display_fqdn takes priority when all fields present
        test_data_all_fields = [{
            "id": "vuln_all_fields",
            "asset": {
                "ipv4_addresses": ["10.0.0.1"],
                "display_fqdn": "server.example.com",
                "host_name": "server"
            },
            "definition": {"id": 1, "name": "Test", "description": "Test"},
            "port": 80
        }]

        self.plugin.parseOutputString(json.dumps(test_data_all_fields))
        vuln_call = self.plugin.createAndAddVulnWebToService.call_args[1]
        assert vuln_call["website"] == "server.example.com"

        # Test 2: host_name used when display_fqdn is missing/empty
        self.plugin.createAndAddVulnWebToService.reset_mock()
        test_data_no_fqdn = [{
            "id": "vuln_no_fqdn",
            "asset": {
                "ipv4_addresses": ["10.0.0.2"],
                "host_name": "hostname.local"
            },
            "definition": {"id": 2, "name": "Test", "description": "Test"},
            "port": 443
        }]

        self.plugin.parseOutputString(json.dumps(test_data_no_fqdn))
        vuln_call = self.plugin.createAndAddVulnWebToService.call_args[1]
        assert vuln_call["website"] == "hostname.local"

        # Test 3: IP used as last resort when both hostname fields missing
        self.plugin.createAndAddVulnWebToService.reset_mock()
        test_data_ip_only = [{
            "id": "vuln_ip_only",
            "asset": {
                "ipv4_addresses": ["10.0.0.3"]
            },
            "definition": {"id": 3, "name": "Test", "description": "Test"},
            "port": 8080
        }]

        self.plugin.parseOutputString(json.dumps(test_data_ip_only))
        vuln_call = self.plugin.createAndAddVulnWebToService.call_args[1]
        assert vuln_call["website"] == "10.0.0.3"

    def test_hostname_from_previous_vuln(self):
        """Test that hostname is properly set from previous VulnerabilityWeb"""

        report_filename = DUMMY_FILES_FOLDER / "tenableio_json.json"
        assert os.path.isfile(report_filename) is True

        # Mocks make this test brake if we use self here.
        plugin = TenableIOJSONExport()
        plugin.processReport(report_filename)
        plugin_json = json.loads(plugin.get_json())

        assert len(plugin_json["hosts"]) == 1
        assert set(plugin_json["hosts"][0]["hostnames"]) == {"server.example.com", "server"}
        assert len(plugin_json["hosts"][0]["services"]) == 2
        assert plugin_json["hosts"][0]["services"][0]["vulnerabilities"][0]["website"] == "server.example.com"
        assert plugin_json["hosts"][0]["services"][1]["vulnerabilities"][0]["website"] in ["server.example.com", "server"]

    def test_create_plugin_function(self):
        """Test the createPlugin factory function (covers line 174)"""
        from faraday_plugins.plugins.repo.tenableio_export_json.plugin import createPlugin

        plugin_instance = createPlugin()
        assert isinstance(plugin_instance, TenableIOJSONExport)
        assert plugin_instance.id == "tenableio_export_json"
        assert plugin_instance.name == "Tenable IO JSON Vuln Export Plugin"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
