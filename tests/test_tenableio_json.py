"""
Test cases for Tenable IO JSON Export Plugin
"""

import json
import pytest
from unittest.mock import Mock, patch
from faraday_plugins.plugins.repo.tenableio_export_json.plugin import TenableIOJSONExport


class TestTenableIOJSONExport:
    """Test suite for Tenable IO JSON Export Plugin"""
    
    def setup_method(self):
        """Setup test environment before each test"""
        self.plugin = TenableIOJSONExport()
        self.plugin.logger = Mock()
        
        # Mock the host/service/vuln creation methods
        self.plugin.createAndAddHost = Mock(return_value="host_id_123")
        self.plugin.createAndAddServiceToHost = Mock(return_value="service_id_456")
        self.plugin.createAndAddVulnToHost = Mock()
        self.plugin.createAndAddVulnToService = Mock()
    
    def test_valid_vulnerability_with_port(self):
        """Test parsing a valid vulnerability with port (should create service vulnerability)"""
        test_data = [{
            "id": "vuln_001",
            "asset": {
                "id": "asset_001",
                "display_ipv4_address": "192.168.1.100",
                "host_name": "webserver01",
                "display_fqdn": "webserver01.example.com",
                "operating_system": "Linux"
            },
            "definition": {
                "id": 12345,
                "name": "SSH Weak Encryption",
                "description": "The SSH service supports weak encryption algorithms",
                "cve": ["CVE-2023-1234"],
                "see_also": ["https://example.com/ref1"]
            },
            "severity": 3,
            "state": "ACTIVE",
            "protocol": "TCP",
            "port": 22,
            "output": "SSH-2.0-OpenSSH_7.4\nWeak ciphers detected: 3des-cbc"
        }]
        
        self.plugin.parseOutputString(json.dumps(test_data))
        
        # Verify host creation with correct IP
        self.plugin.createAndAddHost.assert_called_once_with(
            name="192.168.1.100",
            os="Linux",
            hostnames=["webserver01", "webserver01.example.com"]
        )
        
        # Verify service creation
        self.plugin.createAndAddServiceToHost.assert_called_once_with(
            host_id="host_id_123",
            name="tcp/22",
            protocol="tcp",
            ports=[22],
            status="open"
        )
        
        # Verify service vulnerability creation (not host vulnerability)
        self.plugin.createAndAddVulnToService.assert_called_once()
        self.plugin.createAndAddVulnToHost.assert_not_called()
        
        # Verify vulnerability data
        vuln_call = self.plugin.createAndAddVulnToService.call_args[1]
        assert vuln_call["name"] == "SSH Weak Encryption"
        assert vuln_call["severity"] == "high"
        assert vuln_call["status"] == "open"
        assert vuln_call["data"] == "SSH-2.0-OpenSSH_7.4\nWeak ciphers detected: 3des-cbc"
    
    def test_vulnerability_without_port(self):
        """Test parsing vulnerability without port (should create host vulnerability)"""
        test_data = [{
            "id": "vuln_002",
            "asset": {
                "display_ipv4_address": "10.0.0.50",
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
                    "display_ipv4_address": "172.16.0.1"
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
                "data": {"id": "test2", "asset": {"host_name": "server"}},
                "error_msg": "Omitting vulnerability test2: required field asset.display_ipv4_address is missing"
            },
            {
                "data": {"id": "test3", "asset": {"display_ipv4_address": ""}},
                "error_msg": "Omitting vulnerability test3: required field asset.display_ipv4_address is missing"
            },
            {
                "data": {"id": "test4", "asset": {"display_ipv4_address": "   "}},
                "error_msg": "Omitting vulnerability test4: required field asset.display_ipv4_address is missing"
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
                    "display_ipv4_address": "192.168.1.1",
                    "host_name": "server01",
                    "display_fqdn": "server01.domain.com"
                },
                "expected_hostnames": ["server01", "server01.domain.com"]
            },
            {
                "asset": {
                    "display_ipv4_address": "192.168.1.2",
                    "display_fqdn": "server02.domain.com"
                },
                "expected_hostnames": ["server02.domain.com"]
            },
            {
                "asset": {
                    "display_ipv4_address": "192.168.1.3",
                    "host_name": "server03"
                },
                "expected_hostnames": ["server03"]
            },
            {
                "asset": {
                    "display_ipv4_address": "192.168.1.4"
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
            assert call_args["hostnames"] == test_case["expected_hostnames"]
    
    def test_output_field_processing(self):
        """Test output field truncation and whitespace handling"""
        # Test with long output (should be truncated to 10,000 chars)
        long_output = "A" * 15000
        test_data = [{
            "id": "test_output",
            "asset": {"display_ipv4_address": "10.0.0.1"},
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
            "asset": {"display_ipv4_address": "10.0.0.2"},
            "definition": {"id": 1, "name": "Test", "description": "Test"},
            "output": f"  {test_output}  "  # With external whitespace
        }]
        
        self.plugin.parseOutputString(json.dumps(test_data))
        
        vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
        # Internal formatting preserved, external whitespace stripped
        assert vuln_call["data"] == test_output
    
    def test_service_name_format(self):
        """Test that service name follows the format protocol/port"""
        test_cases = [
            {"protocol": "TCP", "port": 80, "expected": "tcp/80"},
            {"protocol": "UDP", "port": 53, "expected": "udp/53"},
            {"protocol": "tcp", "port": 443, "expected": "tcp/443"},
            {"port": 8080, "expected": "tcp/8080"}  # Default to tcp
        ]
        
        for test_case in test_cases:
            self.plugin.createAndAddServiceToHost.reset_mock()
            
            vuln_data = {
                "id": "test_service",
                "asset": {"display_ipv4_address": "10.0.0.3"},
                "definition": {"id": 1, "name": "Test", "description": "Test"},
                "port": test_case["port"]
            }
            
            if "protocol" in test_case:
                vuln_data["protocol"] = test_case["protocol"]
            
            self.plugin.parseOutputString(json.dumps([vuln_data]))
            
            # Verify service name format
            call_args = self.plugin.createAndAddServiceToHost.call_args[1]
            assert call_args["name"] == test_case["expected"]
            assert call_args["protocol"] == test_case["expected"].split("/")[0]
    
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
                "asset": {"display_ipv4_address": "10.0.0.4"},
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
                "asset": {"display_ipv4_address": "10.0.0.5"},
                "definition": {"id": 1, "name": "Test", "description": "Test"}
            }]
            
            if input_severity is not None:
                test_data[0]["severity"] = input_severity
            
            self.plugin.parseOutputString(json.dumps(test_data))
            
            vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
            assert vuln_call["severity"] == expected_severity
    
    def test_example_json_from_user_story(self):
        """Test with the example JSON from the user story"""
        test_data = [{
            "id": "000c9326-cc6d-5c4f-b20c-32ab5937cee6",
            "asset": {
                "id": "f3d3e5e3-abb4-41e3-ad3b-6adf7a3b51dc",
                "name": "wbkp-prpm001",
                "display_ipv4_address": "172.16.4.1",
                "display_fqdn": "wbkp-prpm001.net01.intra",
                "host_name": "wbkp-prpm001"
            },
            "definition": {
                "id": 169783,
                "name": "Security Updates for Windows Malicious Software Removal Tool (January 2023)",
                "description": "Missing security updates"
            },
            "severity": 2,
            "state": "FIXED",
            "protocol": "TCP",
            "port": 445
        }]
        
        self.plugin.parseOutputString(json.dumps(test_data))
        
        # Verify correct host creation
        self.plugin.createAndAddHost.assert_called_once_with(
            name="172.16.4.1",  # ASSET field shows IP
            os="unknown",
            hostnames=["wbkp-prpm001", "wbkp-prpm001.net01.intra"]
        )
        
        # Verify service vulnerability created (port exists and is valid)
        self.plugin.createAndAddServiceToHost.assert_called_once_with(
            host_id="host_id_123",
            name="tcp/445",
            protocol="tcp",
            ports=[445],
            status="open"
        )
        
        # Verify vulnerability details
        vuln_call = self.plugin.createAndAddVulnToService.call_args[1]
        assert vuln_call["severity"] == "medium"
        assert vuln_call["status"] == "closed"  # FIXED maps to closed
        assert vuln_call["data"] == "N/A"  # No output field in example


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
                "display_ipv4_address": "192.168.1.100",
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
            "Omitting vulnerability vuln_missing_def: definition object is missing required fields"
        )
        self.plugin.createAndAddHost.assert_not_called()
    
    def test_cvss_vectors_present(self):
        """Test CVSS vector processing when CVSS data exists (covers lines 107-108)"""
        test_data = [{
            "id": "vuln_with_cvss",
            "asset": {
                "display_ipv4_address": "192.168.1.100"
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
        assert vuln_call["cvss2"]["vector_string"] == "AV:N/AC:L/Au:N/C:P/I:N/A:N"
        assert vuln_call["cvss3"]["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        assert vuln_call["cvss4"]["vector_string"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N"
    
    def test_missing_description_uses_solution(self):
        """Test that when description is missing, solution field is used instead"""
        test_data = [{
            "id": "vuln_no_desc",
            "asset": {
                "display_ipv4_address": "192.168.1.100"
            },
            "definition": {
                "id": 12345,
                "name": "Test Vulnerability",
                "solution": "Apply the latest security patches"
                # No description field
            },
            "severity": 2
        }]
        
        self.plugin.parseOutputString(json.dumps(test_data))
        
        # Verify solution is used as description
        vuln_call = self.plugin.createAndAddVulnToHost.call_args[1]
        assert vuln_call["desc"] == "Apply the latest security patches"
    
    def test_create_plugin_function(self):
        """Test the createPlugin factory function (covers line 174)"""
        from faraday_plugins.plugins.repo.tenableio_export_json.plugin import createPlugin
        
        # Test that createPlugin returns a TenableIOJSONExport instance
        plugin_instance = createPlugin()
        assert isinstance(plugin_instance, TenableIOJSONExport)
        assert plugin_instance.id == "tenableio_export_json"
        assert plugin_instance.name == "Tenable IO JSON Vuln Export Plugin"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])