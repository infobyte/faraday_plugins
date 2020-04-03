#!/usr/bin/env python
import os
import shutil
import json
import click
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer
from faraday_plugins.plugins.plugin import PluginBase
from faraday_plugins.plugins.plugins_utils import generate_report_summary

BLACK_LIST = [
    'LICENSE',
    'README.md',
    '.gitignore',
    '.gitkeep',
    'faraday_plugins_tests',
]

REPORT_COLLECTION_DIR = './report-collection'
FARADAY_PLUGINS_TESTS_DIR = 'faraday_plugins_tests'


def list_report_files():
    report_filenames = os.walk(REPORT_COLLECTION_DIR)
    for root, directory, filenames in report_filenames:
        if '.git' in directory or FARADAY_PLUGINS_TESTS_DIR in root:
            continue
        for filename in filenames:
            if filename in BLACK_LIST:
                continue
            if '.git' in root:
                continue
            yield os.path.join(root, filename)


@click.command()
@click.option('--force', is_flag=True)
def generate_reports_tests(force):
    generated_summaries = 0
    analysed_reports = 0
    click.echo("Generate Faraday Plugins Tests Summary")
    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    for report_file_path in list_report_files():
        plugin: PluginBase = analyzer.get_plugin(report_file_path)
        if not plugin:
            continue
        else:
            analysed_reports += 1
            report_file_name = os.path.basename(report_file_path)
            plugin_name = plugin.id
            plugin_path = os.path.join(REPORT_COLLECTION_DIR, FARADAY_PLUGINS_TESTS_DIR, plugin_name)
            if not os.path.isdir(plugin_path):
                os.mkdir(plugin_path)
            dst_report_file_path = os.path.join(plugin_path, report_file_name)
            summary_needed = False
            summary_file = f"{os.path.splitext(dst_report_file_path)[0]}_summary.json"
            if not os.path.isfile(dst_report_file_path) or force:
                summary_needed = True
                shutil.copyfile(report_file_path, dst_report_file_path)
            if not os.path.isfile(summary_file) or force:
                summary_needed = True
            if summary_needed:
                try:
                    plugin.processReport(report_file_path)
                    plugin_json = json.loads(plugin.get_json())
                    click.echo(f"Generate Summary for: {dst_report_file_path} [{plugin}]")
                    summary = generate_report_summary(plugin_json)
                    with open(summary_file, "w") as f:
                        json.dump(summary, f)
                    generated_summaries += 1
                except Exception as e:
                    click.echo(f"Error generating summary for file: {report_file_path} [{e}]")
    click.echo(f"Generated {generated_summaries} summaries of {analysed_reports} reports")


if __name__ == "__main__":
    generate_reports_tests()