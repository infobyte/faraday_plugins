import json
import os
from pprint import pprint
from pathlib import Path

from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer

DUMMY_FILES_FOLDER = Path.cwd() / "tests" / "data"


def test_boolean_fields_when_uppercase():
    report_filename = DUMMY_FILES_FOLDER / "dummy_faraday_csv_report.csv"

    assert os.path.isfile(report_filename) is True

    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    plugin = analyzer.get_plugin(report_filename)

    assert plugin is not None

    plugin.processReport(report_filename)
    plugin_json = json.loads(plugin.get_json())

    # Web Vulnerability
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][0]['confirmed'] is True
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][0]['type'] == 'VulnerabilityWeb'
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][0]['impact']['accountability'] is False
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][0]['impact']['availability'] is False
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][0]['impact']['confidentiality'] is True
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][0]['impact']['integrity'] is False

    # Normal Vulnerability associated to a service
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][1]['confirmed'] is True
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][1]['type'] == 'Vulnerability'
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][1]['impact']['accountability'] is False
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][1]['impact']['availability'] is True
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][1]['impact']['confidentiality'] is True
    assert plugin_json['hosts'][0]['services'][0]['vulnerabilities'][1]['impact']['integrity'] is True

    # Normal Vulnerability
    assert plugin_json['hosts'][0]['vulnerabilities'][0]['confirmed'] is True
    assert plugin_json['hosts'][0]['vulnerabilities'][0]['type'] == 'Vulnerability'
    assert plugin_json['hosts'][0]['vulnerabilities'][0]['impact']['accountability'] is False
    assert plugin_json['hosts'][0]['vulnerabilities'][0]['impact']['availability'] is True
    assert plugin_json['hosts'][0]['vulnerabilities'][0]['impact']['confidentiality'] is True
    assert plugin_json['hosts'][0]['vulnerabilities'][0]['impact']['integrity'] is True
