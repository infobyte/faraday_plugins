import logging
import os
import sys
import json
import click
import subprocess
import shlex
import getpass

from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer, CommandAnalyzer
from faraday_plugins.plugins.plugins_utils import get_report_summary
from faraday_plugins.plugins.plugin import PluginByExtension

root_logger = logging.getLogger("faraday")
if not root_logger.handlers:
    PLUGIN_DEBUG = os.environ.get("PLUGIN_DEBUG", "0")
    if PLUGIN_DEBUG == "1":
        out_hdlr = logging.StreamHandler(sys.stdout)
        out_hdlr.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s [%(filename)s:%(lineno)s - %(funcName)s()]  %(message)s'))
        out_hdlr.setLevel(logging.DEBUG)
        root_logger.addHandler(out_hdlr)
        root_logger.setLevel(logging.DEBUG)


@click.group()
def cli():
    pass


@cli.command()
@click.option('-cpf', '--custom-plugins-folder', type=str)
def list(custom_plugins_folder):
    plugins_manager = PluginsManager(custom_plugins_folder)
    click.echo("Available Plugins:")
    loaded_plugins = 0
    for plugin_id, plugin in plugins_manager.get_plugins():
        console_enabled = plugin._command_regex is not None
        console_enabled_color = "green" if console_enabled else "red"
        console_enabled_text = click.style(f"{console_enabled}", fg=console_enabled_color)
        report_enabled = isinstance(plugin, PluginByExtension)
        report_enabled_color = "green" if report_enabled else "red"
        report_enabled_text = click.style(f"{report_enabled}", fg=report_enabled_color)
        click.echo(f"{plugin.id:15}  - [Console: {console_enabled_text:>15} - Report: {report_enabled_text:>15}] - {plugin.name} ")

        loaded_plugins += 1
    click.echo(f"Loaded Plugins: {loaded_plugins}")


@cli.command()
@click.argument('plugin_id')
@click.argument('report_file')
@click.option('-cpf', '--custom-plugins-folder', type=str)
def process_report(plugin_id, report_file, custom_plugins_folder):
    if not os.path.isfile(report_file):
        click.echo(f"File {report_file} Don't Exists")
    else:
        plugins_manager = PluginsManager(custom_plugins_folder)
        plugin = plugins_manager.get_plugin(plugin_id)
        if plugin:
            plugin.processReport(report_file)
            click.echo(json.dumps(plugin.get_data(), indent=4))
        else:
            click.echo(f"Unknown Plugin: {plugin_id}")


@cli.command()
@click.argument('plugin_id')
@click.argument('command')
@click.option('-cpf', '--custom-plugins-folder', type=str)
@click.option('-dr', '--dont-run', is_flag=True)
def process_command(plugin_id, command, custom_plugins_folder, dont_run):
    plugins_manager = PluginsManager(custom_plugins_folder)
    plugin = plugins_manager.get_plugin(plugin_id)
    if plugin:
        modified_command = plugin.processCommandString(getpass.getuser(), "", command)
        if modified_command:
            command = modified_command
        if not dont_run:
            click.echo(click.style(f"Running command: {command}", fg="green"))
            command_result = subprocess.run(shlex.split(command), capture_output=True)
            if command_result.returncode == 0:
                plugin.processOutput(command_result.stdout.decode('utf-8'))
                click.echo(json.dumps(plugin.get_data(), indent=4))
            else:
                click.echo(click.style("Command execution error:", fg="red"))
                click.echo(command_result.stderr)
        else:
            click.echo(click.style(f"Command: {command}", fg="green"))
    else:
        click.echo(f"Unknown Plugin: {plugin_id}")


@cli.command()
@click.argument('report_file')
@click.option('-cpf', '--custom-plugins-folder', type=str)
def detect_report(report_file, custom_plugins_folder):
    if not os.path.isfile(report_file):
        click.echo(f"File {report_file} Don't Exists")
    else:
        plugins_manager = PluginsManager(custom_plugins_folder)
        analyzer = ReportAnalyzer(plugins_manager)
        plugin = analyzer.get_plugin(report_file)
        if plugin:
            click.echo(plugin)
        else:
            click.echo(f"Failed to detect")


@cli.command()
@click.argument('command')
@click.option('-cpf', '--custom-plugins-folder', type=str)
def detect_command(command, custom_plugins_folder):
    plugins_manager = PluginsManager(custom_plugins_folder)
    analyzer = CommandAnalyzer(plugins_manager)
    plugin = analyzer.get_plugin(command)
    if plugin:
        click.echo(plugin)
    else:
        click.echo(f"Failed to detect")


@cli.command()
@click.argument('plugin_id')
@click.argument('report_file')
@click.option('-cpf', '--custom-plugins-folder', type=str)
def get_summary(plugin_id, report_file, custom_plugins_folder):
    if not os.path.isfile(report_file):
        click.echo(f"File {report_file} Don't Exists")
    else:
        plugins_manager = PluginsManager(custom_plugins_folder)
        plugin = plugins_manager.get_plugin(plugin_id)
        if plugin:
            plugin.processReport(report_file)
            report_json = json.loads(plugin.get_json())
            click.echo(f"Report Summary for file [{plugin.id}]: {report_file}")
            click.echo(json.dumps(get_report_summary(report_json), indent=4))
        else:
            click.echo(f"Unknown Plugin: {plugin_id}")
