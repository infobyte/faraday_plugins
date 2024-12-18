import json
import os
from pprint import pprint
from pathlib import Path

from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer

DUMMY_FILES_FOLDER = Path.cwd() / "tests" / "data" / "saint"


def test_missing_fields():
    report_filename = DUMMY_FILES_FOLDER / "saint_missing_fields.csv"

    assert os.path.isfile(report_filename) is True

    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    plugin = analyzer.get_plugin(report_filename)

    assert plugin is not None

    plugin.processReport(report_filename)
    plugin_json = json.loads(plugin.get_json())
    assert len(plugin_json['hosts']) == 1


def get_host(search: str, hosts: dict) -> dict:
    for host in hosts:
        if search == host.get("ip"):
            return host
    return {}


def test_all_fields():
    report_filename = DUMMY_FILES_FOLDER / "saint_ok.csv"

    assert os.path.isfile(report_filename) is True

    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    plugin = analyzer.get_plugin(report_filename)

    assert plugin is not None

    plugin.processReport(report_filename)
    plugin_json = json.loads(plugin.get_json())

    assert len(plugin_json['hosts']) == 3

    assert set(["127.0.0.1", "127.0.0.2", "127.0.0.3"]) == {host['ip'] for host in plugin_json['hosts']}

    assert len(get_host("127.0.0.1", plugin_json['hosts']).get("hostnames")) == 2
    assert len(get_host("127.0.0.2", plugin_json['hosts']).get("hostnames")) == 1
    assert len(get_host("127.0.0.3", plugin_json['hosts']).get("hostnames")) == 0

    assert "127.0.0.1" in get_host("127.0.0.1", plugin_json['hosts']).get("hostnames")
    assert "127.0.0.2" in get_host("127.0.0.1", plugin_json['hosts']).get("hostnames")
    assert "127.0.0.1" in get_host("127.0.0.2", plugin_json['hosts']).get("hostnames")

    assert len(get_host("127.0.0.1", plugin_json['hosts']).get("vulnerabilities", [])) == 2
    assert len(get_host("127.0.0.2", plugin_json['hosts']).get("vulnerabilities", [])) == 1
    assert len(get_host("127.0.0.3", plugin_json['hosts']).get("vulnerabilities", [])) == 1
