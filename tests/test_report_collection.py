import os
import socket
import json
import pytest
from pathlib import Path
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer
from faraday_plugins.plugins.plugin import PluginBase
from faraday.server.api.modules.bulk_create import BulkCreateSchema

BLACK_LIST = [
    'LICENSE',
    'README.md',
    '.gitignore',
    '.gitkeep',
    'faraday_plugins_tests',

]

plugins_manager = PluginsManager(hostname_resolution=False)
analyzer = ReportAnalyzer(plugins_manager)

PLUGINS_CACHE = {}
REPORTS_JSON_CACHE = {}

SKIP_IP_PLUGINS = ['Fortify']

REPORTS_SUMMARY_DIR = './report-collection/faraday_plugins_tests'


def get_plugin_from_cache(report_file):
    plugin = PLUGINS_CACHE.get(report_file)
    if not plugin:
        plugin: PluginBase = analyzer.get_plugin(report_file)
        if plugin:
            save_plugin_in_cache(report_file, plugin)
    return plugin


def save_plugin_in_cache(report_file, plugin):
    if report_file not in PLUGINS_CACHE:
        PLUGINS_CACHE[report_file] = plugin


def get_report_json_from_cache(report_file):
    plugin_json = REPORTS_JSON_CACHE.get(report_file)
    if not plugin_json:
        plugin = get_plugin_from_cache(report_file)
        if plugin:
            plugin.processReport(Path(report_file))
            plugin_json = json.loads(plugin.get_json())
            REPORTS_JSON_CACHE[report_file] = plugin_json
    else:
        plugin = get_plugin_from_cache(report_file)
    return plugin, plugin_json


def list_report_files():
    report_filenames = os.walk(REPORTS_SUMMARY_DIR)
    for plugin_folder, directory, filenames in report_filenames:
        if '.git' in directory or 'faraday_plugins_tests' in directory:
            continue
        for filename in filenames:
            if filename in BLACK_LIST:
                continue
            if '.git' in plugin_folder:
                continue
            if not filename.endswith('_summary.json'):
                yield Path(plugin_folder).name, os.path.join(plugin_folder, filename)


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except OSError:
            return False
        return address.count('.') == 3
    except OSError:  # not a valid address
        return False
    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except OSError:  # not a valid address
        return False
    return True


def is_valid_ip_address(address):
    return (is_valid_ipv4_address(address) or is_valid_ipv6_address(address))

def test_reports_collection_exists():
    assert os.path.isdir(REPORTS_SUMMARY_DIR) is True, "Please clone the report-collection repo!"

@pytest.mark.parametrize("report_filename_and_folder", list_report_files())
def test_autodetected_on_all_report_collection(report_filename_and_folder):
    plugin_folder = report_filename_and_folder[0]
    report_filename = report_filename_and_folder[1]
    plugin: PluginBase = get_plugin_from_cache(report_filename)
    assert plugin, report_filename
    assert plugin.id == plugin_folder


@pytest.mark.skip(reason="Fail until release")
@pytest.mark.parametrize("report_filename_and_folder", list_report_files())
def test_schema_on_all_reports(report_filename_and_folder):
    report_filename = report_filename_and_folder[1]
    plugin, plugin_json = get_report_json_from_cache(report_filename)
    if plugin_json:
        serializer = BulkCreateSchema()
        res = serializer.loads(json.dumps(plugin_json))
        assert set(res.keys()) == {'hosts', 'command'}




@pytest.mark.skip(reason="Skip validate ip format")
@pytest.mark.parametrize("report_filename_and_folder", list_report_files())
def test_host_ips_all_reports(report_filename_and_folder):
    report_filename = report_filename_and_folder[1]
    plugin, plugin_json = get_report_json_from_cache(report_filename)
    if plugin_json:
        if plugin.id not in SKIP_IP_PLUGINS:
            for host in plugin_json['hosts']:
                assert is_valid_ip_address(host['ip']) is True


@pytest.mark.parametrize("report_filename_and_folder", list_report_files())
def test_summary_reports(report_filename_and_folder):
    report_filename = report_filename_and_folder[1]
    plugin, plugin_json = get_report_json_from_cache(report_filename)
    if plugin_json:
        summary_file = f"{os.path.splitext(report_filename)[0]}_summary.json"
        assert os.path.isfile(summary_file) is True
        with open(summary_file) as f:
            saved_summary = json.load(f)
        summary = plugin.get_summary()
        vuln_hashes = set(summary['vuln_hashes'])
        saved_vuln_hashes = set(saved_summary.get('vuln_hashes', []))
        assert summary['hosts'] == saved_summary['hosts']
        assert summary['services'] == saved_summary['services']
        assert summary['hosts_vulns'] == saved_summary['hosts_vulns']
        assert summary['services_vulns'] == saved_summary['services_vulns']
        assert summary['severity_vulns'] == saved_summary['severity_vulns']
        assert vuln_hashes == saved_vuln_hashes


@pytest.mark.performance
@pytest.mark.parametrize("report_filename_and_folder", list_report_files())
def test_detected_tools_on_all_report_collection(report_filename_and_folder, benchmark):
    report_filename = report_filename_and_folder[1]
    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    plugin: PluginBase = analyzer.get_plugin(report_filename)
    if not plugin:
        return
    assert plugin, report_filename
    benchmark(plugin.processReport, report_filename)
    plugin_json = json.loads(plugin.get_json())
    assert "hosts" in plugin_json
    assert "command" in plugin_json
    assert os.path.isfile(report_filename) is True
