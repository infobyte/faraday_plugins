import os

import pytest
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer


def list_report_files():
    report_filenames = os.walk('./report-collection')

    for root, directory, filenames in report_filenames:
        for filename in filenames:
            yield os.path.join(root, filename)


@pytest.mark.parametrize("report_filename", list_report_files())
def test_autodetection_on_all_report_collection(report_filename):
    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    plugin = analyzer.get_plugin(report_filename)
    assert plugin, report_filename

    #assert True == False
