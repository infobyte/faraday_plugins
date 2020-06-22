import json
import os
import re
from click.testing import CliRunner
from faraday_plugins.commands import cli


def test_list_plugins():
    runner = CliRunner()
    result = runner.invoke(cli, ['list-plugins'])
    assert result.exit_code == 0
    loaded_plugins = re.search(r'Loaded Plugins: (?P<loaded_plugins>\d+)', result.output)
    assert loaded_plugins
    assert int(loaded_plugins.groupdict().get('loaded_plugins', 0)) > 0


def test_detect_invalid_command():
    runner = CliRunner()
    result = runner.invoke(cli, ['detect-command', 'invalid_command'])
    assert result.exit_code == 0
    assert result.output.strip() == "Failed to detect command: invalid_command"


def test_detect_command():
    runner = CliRunner()
    result = runner.invoke(cli, ['detect-command', 'ping -c www.google.com'])
    assert result.exit_code == 0
    assert result.output.strip() == "Faraday Plugin: ping"


def test_detect_report():
    report_file = os.path.join('./report-collection', 'faraday_plugins_tests', 'Nmap', 'nmap_5.21.xml')
    runner = CliRunner()
    result = runner.invoke(cli, ['detect-report', report_file])
    assert result.exit_code == 0
    assert "Faraday Plugin: Nmap" == result.output.strip()


def test_detect_report_dont_exists():
    report_file = os.path.join('../report-collection', 'faraday_plugins_tests', 'Nmap', 'nmap_5.21.xml')
    runner = CliRunner()
    result = runner.invoke(cli, ['detect-report', report_file])
    assert result.exit_code == 0
    assert "Don't Exists" in result.output.strip()


def test_process_report():
    report_file = os.path.join('./report-collection', 'faraday_plugins_tests', 'Nmap', 'nmap_5.21.xml')
    summary_file = os.path.join('./report-collection', 'faraday_plugins_tests', 'Nmap', 'nmap_5.21_summary.json')
    runner = CliRunner()
    result = runner.invoke(cli, ['process-report', report_file, '--summary'])
    assert result.exit_code == 0
    summary = json.loads(result.output.strip())
    with open(summary_file) as f:
        saved_summary = json.load(f)
    vuln_hashes = set(summary['vuln_hashes'])
    saved_vuln_hashes = set(saved_summary.get('vuln_hashes', []))
    assert summary['hosts'] == saved_summary['hosts']
    assert summary['services'] == saved_summary['services']
    assert summary['hosts_vulns'] == saved_summary['hosts_vulns']
    assert summary['services_vulns'] == saved_summary['services_vulns']
    assert summary['severity_vulns'] == saved_summary['severity_vulns']
    assert vuln_hashes == saved_vuln_hashes