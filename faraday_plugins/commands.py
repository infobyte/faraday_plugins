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
def list_plugins(custom_plugins_folder):
    plugins_manager = PluginsManager(custom_plugins_folder)
    click.echo(click.style("Available Plugins:", fg="cyan"))
    loaded_plugins = 0
    for plugin_id, plugin in plugins_manager.get_plugins():
        console_enabled = plugin._command_regex is not None
        console_enabled_color = "green" if console_enabled else "red"
        console_enabled_text = click.style(f"{'Yes' if console_enabled else 'No'}", fg=console_enabled_color)
        report_enabled = isinstance(plugin, PluginByExtension)
        report_enabled_color = "green" if report_enabled else "red"
        report_enabled_text = click.style(f"{'Yes' if report_enabled else 'No'}", fg=report_enabled_color)
        click.echo(f"{plugin.id:15}  - [Command: {console_enabled_text:>12} - Report: {report_enabled_text:>12}] - {plugin.name} ")

        loaded_plugins += 1
    click.echo(click.style(f"Loaded Plugins: {loaded_plugins}", fg="cyan"))


@cli.command()
@click.argument('report_file')
@click.option('--plugin_id', type=str)
@click.option('-cpf', '--custom-plugins-folder', type=str)
@click.option('--summary', is_flag=True)
def process_report(report_file, plugin_id, custom_plugins_folder, summary):
    if not os.path.isfile(report_file):
        click.echo(click.style(f"File {report_file} Don't Exists", fg="red"))
    else:
        plugins_manager = PluginsManager(custom_plugins_folder)
        analyzer = ReportAnalyzer(plugins_manager)
        if plugin_id:
            plugin = plugins_manager.get_plugin(plugin_id)
            if not plugin:
                click.echo(click.style(f"Invalid Plugin: {plugin_id}", fg="red"))
                return
        else:
            plugin = analyzer.get_plugin(report_file)
            if not plugin:
                click.echo(click.style(f"Failed to detect report: {report_file}", fg="red"))
                return
        plugin.processReport(report_file, getpass.getuser())
        if summary:
            click.echo(click.style("\nPlugin Summary: ", fg="cyan"))
            click.echo(json.dumps(plugin.get_summary(), indent=4))
        else:
            click.echo(click.style("\nFaraday API json: ", fg="cyan"))
            click.echo(json.dumps(plugin.get_data(), indent=4))


@cli.command()
@click.argument('command')
@click.option('--plugin_id', type=str)
@click.option('-cpf', '--custom-plugins-folder', type=str)
@click.option('-dr', '--dont-run', is_flag=True)
@click.option('--summary', is_flag=True)
def process_command(command, plugin_id, custom_plugins_folder, dont_run, summary):
    plugins_manager = PluginsManager(custom_plugins_folder)
    analyzer = CommandAnalyzer(plugins_manager)
    if plugin_id:
        plugin = plugins_manager.get_plugin(plugin_id)
        if not plugin:
            click.echo(click.style(f"Invalid Plugin: {plugin_id}", fg="red"))
            return
    else:
        plugin = analyzer.get_plugin(command)
        if not plugin:
            click.echo(click.style(f"Failed to detect command: {command}", fg="red"))
            return
    current_path = os.path.abspath(os.getcwd())
    modified_command = plugin.processCommandString(getpass.getuser(), current_path, command)
    if modified_command:
        command = modified_command
    if not dont_run:
        color_message = click.style("Running command: ", fg="green")
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
            if summary:
                click.echo(click.style("\nPlugin Summary: ", fg="cyan"))
                click.echo(json.dumps(plugin.get_summary(), indent=4))
            else:
                click.echo(click.style("\nFaraday API json: ", fg="cyan"))
                click.echo(json.dumps(plugin.get_data(), indent=4))
        else:
            click.echo(click.style("Command execution error!!", fg="red"))
    else:
        color_message = click.style("Command: ", fg="green")
        click.echo(f"{color_message} {command}")



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
