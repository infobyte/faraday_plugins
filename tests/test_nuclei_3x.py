import pytest
import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch
from faraday_plugins.plugins.repo.nuclei.plugin import (
    NucleiPlugin,
    NucleiV2Parser,
    NucleiV3Parser,
    createPlugin
)


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

        # Impact should now be in technical data (data field), not in impact parameter
        data = log4j_call.get('data', '')
        assert data != '', "Technical data should be present"
        assert 'Impact:' in data, "Impact should be in technical data"
        # Verify the actual impact text is present
        assert any(text in data for text in ["remote code execution", "system compromise"]), \
            "Impact descriptive text should be in technical data"

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

    def test_parser_selection(self):
        """Test the parser selection logic"""
        from faraday_plugins.plugins.repo.nuclei.plugin import _get_parser

        # Test Nuclei 3.x parser selection
        vuln_3x = {
            "info": {
                "impact": "This is a 3.x impact field",
                "metadata": {}
            }
        }
        parser_3x = _get_parser(vuln_3x)
        assert isinstance(parser_3x, NucleiV3Parser)

        # Test Nuclei 2.x parser selection (fallback)
        vuln_2x = {
            "info": {
                "metadata": {
                    "impact": "tag1,tag2,tag3"
                }
            }
        }
        parser_2x = _get_parser(vuln_2x)
        assert isinstance(parser_2x, NucleiV2Parser)

    def test_impact_extraction_v2_returns_string(self):
        """Test NucleiV2Parser returns impact as string for technical data"""
        # Test with comma-separated impact tags (now returned as string)
        vuln_dict = {
            "info": {
                "metadata": {
                    "impact": "high,rce,critical"
                }
            }
        }
        parser = NucleiV2Parser(vuln_dict)
        result = parser.get_impact()
        assert isinstance(result, str), "Impact should be a string"
        assert result == "high,rce,critical"

        # Test with no impact
        vuln_no_impact = {
            "info": {"metadata": {}}
        }
        parser_empty = NucleiV2Parser(vuln_no_impact)
        result_empty = parser_empty.get_impact()
        assert result_empty == ''

        # Test with non-string impact
        vuln_non_string = {
            "info": {"metadata": {"impact": 123}}
        }
        parser_non_string = NucleiV2Parser(vuln_non_string)
        result_non_string = parser_non_string.get_impact()
        assert result_non_string == ''

    def test_impact_extraction_v3_returns_string(self):
        """Test NucleiV3Parser returns impact as string for technical data"""
        # Test with descriptive impact text
        vuln_with_impact = {
            "info": {"impact": "This vulnerability allows remote code execution"}
        }
        parser = NucleiV3Parser(vuln_with_impact)
        result = parser.get_impact()
        assert isinstance(result, str), "Impact should be a string"
        assert result == "This vulnerability allows remote code execution"

        # Test with empty/whitespace impact
        vuln_empty = {
            "info": {"impact": "   "}
        }
        parser_empty = NucleiV3Parser(vuln_empty)
        result_empty = parser_empty.get_impact()
        assert result_empty == ''

        # Test with no impact field
        vuln_no_impact = {
            "info": {}
        }
        parser_no_impact = NucleiV3Parser(vuln_no_impact)
        result_no_impact = parser_no_impact.get_impact()
        assert result_no_impact == ''

    def test_parseOutputString_missing_matched_at(self):
        """Test parseOutputString with missing matched-at field"""
        plugin = NucleiPlugin()
        plugin.logger = Mock()

        # Create test data without matched-at field
        vuln_data = {
            "template-id": "test-template",
            "host": "https://example.com",
            "info": {
                "name": "Test Vuln",
                "severity": "medium"
            }
        }

        with patch('builtins.print') as mock_print, \
             patch('sys.exit') as mock_exit:
            mock_exit.side_effect = SystemExit(1)  # Make sys.exit actually raise
            with pytest.raises(SystemExit):
                plugin.parseOutputString(json.dumps(vuln_data))
            mock_print.assert_called_with('Version not supported, use nuclei 2.5.3 or higher')
            mock_exit.assert_called_with(1)

    def test_parseOutputString_with_reference_formatting(self):
        """Test parseOutputString with various reference formats"""
        plugin = NucleiPlugin()
        plugin.logger = Mock()
        plugin.createAndAddHost = Mock(return_value="host_id")
        plugin.createAndAddServiceToHost = Mock(return_value="service_id")
        plugin.createAndAddVulnWebToService = Mock()
        plugin.resolve_hostname = Mock(return_value="192.168.1.1")

        # Test with reference string starting with "- "
        vuln_data = {
            "template-id": "test-template",
            "host": "https://example.com",
            "matched-at": "https://example.com/test",
            "info": {
                "name": "Test Vuln",
                "severity": "medium",
                "reference": "- https://example1.com\n- https://example2.com\n",
                "references": "- https://ref1.com\n- https://ref2.com"
            }
        }

        plugin.parseOutputString(json.dumps(vuln_data))

        # Verify vulnerability was created
        assert plugin.createAndAddVulnWebToService.called
        call_kwargs = plugin.createAndAddVulnWebToService.call_args[1]
        refs = call_kwargs.get('ref', [])

        # Should contain processed references
        assert 'https://example1.com' in refs
        assert 'https://example2.com' in refs
        assert 'https://ref1.com' in refs
        assert 'https://ref2.com' in refs

    def test_parseOutputString_with_simple_references(self):
        """Test parseOutputString with simple string references"""
        plugin = NucleiPlugin()
        plugin.logger = Mock()
        plugin.createAndAddHost = Mock(return_value="host_id")
        plugin.createAndAddServiceToHost = Mock(return_value="service_id")
        plugin.createAndAddVulnWebToService = Mock()
        plugin.resolve_hostname = Mock(return_value="192.168.1.1")

        # Test with simple string references
        vuln_data = {
            "template-id": "test-template",
            "host": "https://example.com",
            "matched-at": "https://example.com/test",
            "info": {
                "name": "Test Vuln",
                "severity": "medium",
                "reference": "https://simple-ref.com",
                "references": "https://simple-refs.com"
            }
        }

        plugin.parseOutputString(json.dumps(vuln_data))

        assert plugin.createAndAddVulnWebToService.called
        call_kwargs = plugin.createAndAddVulnWebToService.call_args[1]
        refs = call_kwargs.get('ref', [])

        assert 'https://simple-ref.com' in refs
        assert 'https://simple-refs.com' in refs

    def test_parseOutputString_with_string_tags(self):
        """Test parseOutputString with string tags (comma-separated)"""
        plugin = NucleiPlugin()
        plugin.logger = Mock()
        plugin.createAndAddHost = Mock(return_value="host_id")
        plugin.createAndAddServiceToHost = Mock(return_value="service_id")
        plugin.createAndAddVulnWebToService = Mock()
        plugin.resolve_hostname = Mock(return_value="192.168.1.1")

        vuln_data = {
            "template-id": "test-template",
            "host": "https://example.com",
            "matched-at": "https://example.com/test",
            "info": {
                "name": "Test Vuln",
                "severity": "medium",
                "tags": "cve,rce,critical"
            }
        }

        plugin.parseOutputString(json.dumps(vuln_data))

        assert plugin.createAndAddVulnWebToService.called
        call_kwargs = plugin.createAndAddVulnWebToService.call_args[1]
        tags = call_kwargs.get('tags', [])

        assert 'cve' in tags
        assert 'rce' in tags
        assert 'critical' in tags

    def test_processCommandString_without_output_arg(self):
        """Test processCommandString when no output arg is present"""
        plugin = NucleiPlugin()

        command = "nuclei -t templates/ -u example.com"
        result = plugin.processCommandString("user", "/path", command)

        # Check that the command was modified correctly (dynamic output path)
        assert "--json -irr -o" in result
        assert result.startswith("nuclei --json -irr -o")
        assert "-t templates/ -u example.com" in result

    def test_processCommandString_with_existing_output_arg(self):
        """Test processCommandString when output arg already exists"""
        plugin = NucleiPlugin()

        command = "nuclei -t templates/ -o existing.json -u example.com"
        result = plugin.processCommandString("user", "/path", command)

        # Check that existing output arg was replaced
        assert "--json -irr -o" in result
        assert "existing.json" not in result
        assert "-t templates/" in result
        assert "-u example.com" in result

    @patch('subprocess.Popen')
    def test_canParseCommandString_success(self, mock_popen):
        """Test canParseCommandString with successful version check"""
        plugin = NucleiPlugin()
        plugin.command = "nuclei"

        # Mock successful subprocess call
        mock_process = Mock()
        mock_process.stderr.read.return_value = b"Current Version: 2.6.0\n"
        mock_popen.return_value = mock_process

        with patch.object(plugin, 'canParseCommandString', wraps=plugin.canParseCommandString) as mock_super:
            # Mock the super() call to return True
            type(plugin).__bases__[0].canParseCommandString = Mock(return_value=True)

            result = plugin.canParseCommandString("nuclei -t test")
            assert result is True

    @patch('subprocess.Popen')
    def test_canParseCommandString_version_too_old(self, mock_popen):
        """Test canParseCommandString with old version"""
        plugin = NucleiPlugin()
        plugin.command = "nuclei"

        mock_process = Mock()
        mock_process.stderr.read.return_value = b"Current Version: 2.4.0\n"
        mock_popen.return_value = mock_process

        type(plugin).__bases__[0].canParseCommandString = Mock(return_value=True)

        result = plugin.canParseCommandString("nuclei -t test")
        assert result is False

    @patch('subprocess.Popen')
    def test_canParseCommandString_no_version_match(self, mock_popen):
        """Test canParseCommandString when version regex doesn't match"""
        plugin = NucleiPlugin()
        plugin.command = "nuclei"

        mock_process = Mock()
        mock_process.stderr.read.return_value = b"Some other output\n"
        mock_popen.return_value = mock_process

        type(plugin).__bases__[0].canParseCommandString = Mock(return_value=True)

        result = plugin.canParseCommandString("nuclei -t test")
        assert result is False

    @patch('subprocess.Popen')
    def test_canParseCommandString_exception(self, mock_popen):
        """Test canParseCommandString when subprocess raises exception"""
        plugin = NucleiPlugin()
        plugin.command = "nuclei"

        mock_popen.side_effect = Exception("Command not found")

        type(plugin).__bases__[0].canParseCommandString = Mock(return_value=True)

        result = plugin.canParseCommandString("nuclei -t test")
        assert result is False

    def test_canParseCommandString_super_returns_false(self):
        """Test canParseCommandString when super().canParseCommandString returns False"""
        plugin = NucleiPlugin()

        with patch('faraday_plugins.plugins.plugin.PluginMultiLineJsonFormat.canParseCommandString') as mock_super:
            mock_super.return_value = False
            result = plugin.canParseCommandString("invalid command")
            assert result is None

    def test_createPlugin_factory_function(self):
        """Test the createPlugin factory function"""
        plugin = createPlugin()
        assert isinstance(plugin, NucleiPlugin)

        # Test with arguments
        plugin_with_args = createPlugin("arg1", kwarg1="value1")
        assert isinstance(plugin_with_args, NucleiPlugin)
