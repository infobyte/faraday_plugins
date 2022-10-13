import json
import os
import re
import pytest
from click.testing import CliRunner
from faraday_plugins.commands import list_plugins, detect_command, process_command, detect_report, process_report


def test_list_plugins():
    runner = CliRunner()
    result = runner.invoke(list_plugins)
    assert result.exit_code == 0
    loaded_plugins = re.search(r'Loaded Plugins: (?P<loaded_plugins>\d+)', result.output)
    assert loaded_plugins
    assert int(loaded_plugins.groupdict().get('loaded_plugins', 0)) > 0


def test_detect_invalid_command():
    runner = CliRunner()
    result = runner.invoke(detect_command, args=['invalid_command'])
    assert result.exit_code == 0
    assert result.output.strip() == "Failed to detect command: invalid_command"


@pytest.mark.skip(reason="issue with docker image")
def test_detect_command():
    runner = CliRunner()
    result = runner.invoke(detect_command, args=['ping -c 1 www.google.com'])
    assert result.exit_code == 0
    assert result.output.strip() == "Faraday Plugin: ping"


@pytest.mark.skip(reason="issue with docker image")
def test_process_command():
    runner = CliRunner()
    result = runner.invoke(process_command, args=['ping -c 1 www.google.com', '--summary'])
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output.strip())
    assert summary['hosts'] == 1


@pytest.mark.skip(reason="issue with docker image")
def test_process_command_ping():
    runner = CliRunner()
    result = runner.invoke(process_command, args=['ping -c 1 www.google.com'])
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output.strip())

    assert summary['command']["command"] == 'ping'


@pytest.mark.skip(reason="issue with docker image")
def test_process_command_to_file():
    runner = CliRunner()
    with runner.isolated_filesystem() as file_system:
        output_file = os.path.join(file_system, "test.json")
        result = runner.invoke(process_command, args=['ping -c 1 www.google.com',  '-o', output_file])
        assert result.exit_code == 0, result.output
        assert os.path.isfile(output_file)
        with open(output_file) as f:
            vuln_json = json.load(f)
        assert len(vuln_json['hosts']) == 1


def test_detect_report():
    report_file = os.path.join('./report-collection', 'faraday_plugins_tests', 'Nmap', 'nmap_5.21.xml')
    runner = CliRunner()
    result = runner.invoke(detect_report, args=[report_file])
    assert result.exit_code == 0
    assert "Faraday Plugin: Nmap" == result.output.strip()


def test_detect_report_dont_exists():
    report_file = os.path.join('./report-collection', 'faraday_plugins_tests', 'Nmap', 'invalid_report.xml')
    runner = CliRunner()
    result = runner.invoke(detect_report, args=[report_file])
    assert result.exit_code == 0
    assert "Don't Exists" in result.output.strip()


def test_process_report_summary():
    report_file = os.path.join('./report-collection', 'faraday_plugins_tests', 'Nmap', 'nmap_5.21.xml')
    summary_file = os.path.join('./report-collection', 'faraday_plugins_tests', 'Nmap', 'nmap_5.21_summary.json')
    runner = CliRunner()
    result = runner.invoke(process_report, args=[report_file, '--summary'])
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


def test_process_report_ignore_info():
    report_file = os.path.join('./report-collection', 'faraday_plugins_tests', 'Nmap', 'nmap_5.21.xml')
    runner = CliRunner()
    result = runner.invoke(process_report, args=[report_file, '--summary', '--ignore-info'])
    assert result.exit_code == 0
    summary = json.loads(result.output.strip())
    assert summary['hosts'] == 256
    assert summary['services'] == 69
    assert summary['hosts_vulns'] == 0
    assert summary['services_vulns'] == 0


def test_process_report_tags():
    report_file = os.path.join('./report-collection', 'faraday_plugins_tests', 'Acunetix', 'acunetix_valid_dummy.xml')
    runner = CliRunner()
    args = [report_file, '--vuln-tag=vuln_tag', '--service-tag=service_tag', '--host-tag=host_tag']
    result = runner.invoke(process_report, args=args)
    assert result.exit_code == 0
    body = json.loads(result.output.strip())
    assert body['hosts'][0]["tags"][0] == "host_tag"
    assert body['hosts'][0]["services"][0]["tags"][0] == "service_tag"
    assert body['hosts'][0]["services"][0]["vulnerabilities"][0]["tags"][0] == "vuln_tag"
