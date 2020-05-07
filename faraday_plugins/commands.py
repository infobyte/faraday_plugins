import io
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
    click.echo(click.style("Available Plugins:", fg="cyan"))
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
    click.echo(click.style(f"Loaded Plugins: {loaded_plugins}", fg="cyan"))


@cli.command()
@click.argument('plugin_id')
@click.argument('report_file')
@click.option('-cpf', '--custom-plugins-folder', type=str)
def process_report(plugin_id, report_file, custom_plugins_folder):
    if not os.path.isfile(report_file):
        click.echo(click.style(f"File {report_file} Don't Exists", fg="red"))
    else:
        plugins_manager = PluginsManager(custom_plugins_folder)
        plugin = plugins_manager.get_plugin(plugin_id)
        if plugin:
            plugin.processReport(report_file, getpass.getuser())
            click.echo(click.style(f"\nFaraday API json: ", fg="cyan"))
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
        current_path = os.path.abspath(os.getcwd())
        modified_command = plugin.processCommandString(getpass.getuser(), current_path, command)
        if modified_command:
            command = modified_command
        if not dont_run:
            color_message = click.style(f"Running command: ", fg="green")
            click.echo(f"{color_message} {command}\n")
            p = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = io.StringIO()
            while True:
                retcode = p.poll()
                line = p.stdout.readline().decode('utf-8')
                sys.stdout.write(line)
                output.write(line)
                if retcode is not None:
                    extra_lines = map(lambda x: x.decode('utf-8'), p.stdout.readlines())
                    sys.stdout.writelines(line)
                    output.writelines(extra_lines)
                    break
            output_value = output.getvalue()
            if retcode == 0:
                plugin.processOutput(output_value)
                click.echo(click.style(f"\nFaraday API json: ", fg="cyan"))
                click.echo(json.dumps(plugin.get_data(), indent=4))
            else:
                click.echo(click.style("Command execution error!!", fg="red"))
        else:
            color_message = click.style(f"Command: ", fg="green")
            click.echo(f"{color_message} {command}")
    else:
        click.echo(f"Unknown Plugin: {plugin_id}")


@cli.command()
@click.argument('report_file')
@click.option('-cpf', '--custom-plugins-folder', type=str)
def detect_report(report_file, custom_plugins_folder):
    if not os.path.isfile(report_file):
        click.echo(click.style(f"File {report_file} Don't Exists", fg="red"))
    else:
        plugins_manager = PluginsManager(custom_plugins_folder)
        analyzer = ReportAnalyzer(plugins_manager)
        plugin = analyzer.get_plugin(report_file)
        if plugin:
            click.echo(click.style(f"Faraday Plugin: {plugin.id}", fg="cyan"))
        else:
            click.echo(click.style(f"Failed to detect report: {report_file}", fg="red"))


@cli.command()
@click.argument('command')
@click.option('-cpf', '--custom-plugins-folder', type=str)
def detect_command(command, custom_plugins_folder):
    plugins_manager = PluginsManager(custom_plugins_folder)
    analyzer = CommandAnalyzer(plugins_manager)
    plugin = analyzer.get_plugin(command)
    if plugin:
        click.echo(click.style(f"Faraday Plugin: {plugin.id}", fg="cyan"))
    else:
        click.echo(click.style(f"Failed to detect command: {command}", fg="red"))


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
