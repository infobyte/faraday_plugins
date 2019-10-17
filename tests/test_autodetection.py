import os

import pytest
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer

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


@pytest.mark.parametrize("report_filename", list_report_files())
def test_autodetection_on_all_report_collection(report_filename):
    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    plugin = analyzer.get_plugin(report_filename)
    assert plugin, report_filename

    #assert True == False
