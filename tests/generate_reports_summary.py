#!/usr/bin/env python
import hashlib
import os
import shutil
import json
import click
import colorama
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer
from faraday_plugins.plugins.plugin import PluginBase

colorama.init(autoreset=True)

BLACK_LIST = [
    'LICENSE',
    'README.md',
    '.gitignore',
    '.gitkeep',
    'faraday_plugins_tests',
]

REPORT_COLLECTION_DIR = '../report-collection'
FARADAY_PLUGINS_TESTS_DIR = 'faraday_plugins_tests'
REPORTS_CHECKSUM = []

def list_report_files():
    report_filenames = os.walk(os.path.join(REPORT_COLLECTION_DIR))
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
@click.option('--debug', is_flag=False)
def generate_reports_tests(force, debug):
    generated_summaries = 0
    analysed_reports = 0
    click.echo(f"{colorama.Fore.GREEN}Generate Faraday Plugins Tests Summary")
    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    for report_file_path in list_report_files():
        if debug:
            click.echo(f"File: {report_file_path}")
        plugin: PluginBase = analyzer.get_plugin(report_file_path)
        if not plugin:
            click.echo(f"{colorama.Fore.YELLOW}Plugin for file: ({report_file_path}) not found")
        else:
            with open(report_file_path, 'rb') as f:
                m = hashlib.md5(f.read())
            file_checksum = m.hexdigest()
            if file_checksum not in REPORTS_CHECKSUM:
                REPORTS_CHECKSUM.append(file_checksum)
            else:
                click.echo(f"{colorama.Fore.YELLOW}Ignore duplicated file: ({report_file_path})")
                continue
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
                    click.echo(f"{colorama.Fore.GREEN}Generate Summary for: {dst_report_file_path} [{plugin}]")
                    summary = plugin.get_summary()
                    with open(summary_file, "w") as f:
                        json.dump(summary, f)
                    generated_summaries += 1
                except Exception as e:
                    click.echo(f"{colorama.Fore.RED}Error generating summary for file: {report_file_path} [{plugin}]: [{e}]")
    click.echo(f"Generated {generated_summaries} summaries of {analysed_reports} reports")


if __name__ == "__main__":
    generate_reports_tests()
