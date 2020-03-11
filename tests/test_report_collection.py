import os

import json
import pytest
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer
from faraday_plugins.plugins.plugin import PluginBase

BLACK_LIST = [
    'LICENSE',
    'README.md',
    '.gitignore',
    '.gitkeep',
]

def list_report_files():
    report_filenames = os.walk('./report-collection')

    for root, directory, filenames in report_filenames:
        if '.git' in directory:
            continue
        for filename in filenames:
            if filename in BLACK_LIST:
                continue
            if '.git' in root:
                continue
            yield os.path.join(root, filename)


@pytest.mark.skip(reason="Skip auto detection test until we review all the report files")
@pytest.mark.parametrize("report_filename", list_report_files())
def test_autodetected_on_all_report_collection(report_filename):
    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    plugin: PluginBase = analyzer.get_plugin(report_filename)
    assert plugin, report_filename


@pytest.mark.parametrize("report_filename", list_report_files())
def test_detected_tools_on_all_report_collection(report_filename, benchmark):
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
    assert len(plugin_json) == 2
