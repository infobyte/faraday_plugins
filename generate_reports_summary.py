#!/usr/bin/env python
import os
import shutil
import json
import click
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer
from faraday_plugins.plugins.plugin import PluginBase
from collections import defaultdict

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


def generate_summary(plugin, report_file_path):
    click.echo("Generate Summary for: %s" % report_file_path)
    summary = {
        'hosts': 0,
        'services': 0,
        'hosts_vulns': 0,
        'services_vulns': 0,
        'severity_vulns': defaultdict(int)
    }
    summary_file = f"{os.path.splitext(report_file_path)[0]}_summary.json"
    try:
        plugin.processReport(report_file_path)
        plugin_json = json.loads(plugin.get_json())
        summary['hosts'] = len(plugin_json['hosts'])
        summary['hosts_vulns'] = sum(list(map(lambda x: len(x['vulnerabilities']), plugin_json['hosts'])))
        hosts_with_services = filter(lambda x: len(x['services']) > 1, plugin_json['hosts'])
        host_services = list(map(lambda x: x['services'], hosts_with_services))
        summary['services'] = sum(map(lambda x: len(x), host_services))
        services_vulns = 0
        for services in host_services:
            for service in services:
                services_vulns += len(service['vulnerabilities'])
        summary['services_vulns'] = services_vulns
        with open(summary_file) as f:
            json.dump(summary, f)
    except Exception as e:
        click.echo("Error generating summary for file: %s [%s]" % (report_file_path, e))


@click.command()
@click.option('--force', is_flag=True)
def generate_reports_tests(force):
    click.echo("Generate Faraday Plugins Tests Summary")
    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    for report_file_path in list_report_files():
        plugin: PluginBase = analyzer.get_plugin(report_file_path)
        if not plugin:
            continue
        else:
            report_file_name = os.path.basename(report_file_path)
            plugin_name = plugin.id
            plugin_path = os.path.join(REPORT_COLLECTION_DIR, FARADAY_PLUGINS_TESTS_DIR, plugin_name)
            if not os.path.isdir(plugin_path):
                os.mkdir(plugin_path)
            dst_report_file_path = os.path.join(plugin_path, report_file_name)
            summary_needed = False
            if not os.path.isfile(dst_report_file_path):
                summary_needed = True
                shutil.copyfile(report_file_path, dst_report_file_path)
            else:
                if force:
                    summary_needed = True
            if summary_needed:
                generate_summary(plugin, dst_report_file_path)


if __name__ == "__main__":
    generate_reports_tests()