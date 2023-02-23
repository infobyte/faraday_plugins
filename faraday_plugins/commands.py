import getpass
import io
import json
import logging
import os
import shlex
import subprocess # nosec
import sys
from pathlib import Path

import click
from tabulate import tabulate

from faraday_plugins import __version__
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

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, '-v', '--version')
def cli():
    pass


@cli.command()
@click.option('-cpf', '--custom-plugins-folder', type=str)
def list_plugins(custom_plugins_folder):
    plugins_manager = PluginsManager(custom_plugins_folder)
    click.echo(click.style(f"Faraday Plugins v{__version__}", fg="cyan"))
    click.echo(click.style("Available Plugins :", fg="cyan"))
    loaded_plugins = 0
    plugins_data = []
    for plugin_id, plugin in plugins_manager.get_plugins():
        console_enabled = plugin._command_regex is not None
        console_enabled_color = "green" if console_enabled else "red"
        console_enabled_text = click.style(f"{'Yes' if console_enabled else 'No'}", fg=console_enabled_color)
        report_enabled = isinstance(plugin, PluginByExtension)
        report_enabled_color = "green" if report_enabled else "red"
        report_enabled_text = click.style(f"{'Yes' if report_enabled else 'No'}", fg=report_enabled_color)
        plugins_data.append({"Name": plugin.name, "ID": plugin.id, "Command": console_enabled_text,
                             "Report": report_enabled_text})
    click.echo(tabulate(
        plugins_data,
        headers="keys",
        tablefmt="github",
    ))
    click.echo(click.style(f"Loaded Plugins: {len(plugins_data)}", fg="cyan"))


@cli.command()
@click.argument('report_file')
@click.option('--plugin_id', type=str)
@click.option('-cpf', '--custom-plugins-folder', type=str)
@click.option('--summary', is_flag=True)
@click.option('-o', '--output-file', type=click.Path(exists=False))
@click.option('--ignore-info', is_flag=True, help="Ignore information vulnerabilities")
@click.option('-drh', '--dont-resolve-hostname', is_flag=True, help="Dont resolve hostname", default=False)
@click.option('--vuln-tag', help="Vuln tag", default=None)
@click.option('--service-tag', help="Service tag", default=None)
@click.option('--host-tag', help="Host tag", default=None)
def process_report(report_file, plugin_id, custom_plugins_folder, summary, output_file, ignore_info,
                   dont_resolve_hostname, vuln_tag, service_tag, host_tag):
    if not os.path.isfile(report_file):
        click.echo(click.style(f"File {report_file} Don't Exists", fg="red"), err=True)
    else:
        plugins_manager = PluginsManager(custom_plugins_folder,
                                         ignore_info=ignore_info,
                                         hostname_resolution=not dont_resolve_hostname,
                                         vuln_tag=vuln_tag,
                                         service_tag=service_tag,
                                         host_tag=host_tag)
        analyzer = ReportAnalyzer(plugins_manager)
        if plugin_id:
            plugin = plugins_manager.get_plugin(plugin_id)
            if not plugin:
                click.echo(click.style(f"Invalid Plugin: {plugin_id}", fg="red"), err=True)
                return
        else:
            plugin = analyzer.get_plugin(report_file)
            if not plugin:
                click.echo(click.style(f"Failed to detect report: {report_file}", fg="red"), err=True)
                return
        plugin.processReport(Path(report_file), getpass.getuser())
        if summary:
            click.echo(json.dumps(plugin.get_summary(), indent=4))
        else:
            if output_file:
                with open(output_file, "w") as f:
                    json.dump(plugin.get_data(), f)
            else:
                click.echo(json.dumps(plugin.get_data(), indent=4))


@cli.command()
@click.argument('command')
@click.option('--plugin_id', type=str)
@click.option('-cpf', '--custom-plugins-folder', type=str)
@click.option('-dr', '--dont-run', is_flag=True)
@click.option('--summary', is_flag=True)
@click.option('-o', '--output-file', type=click.Path(exists=False))
@click.option('-sh', '--show-output', is_flag=True)
@click.option('--ignore-info', is_flag=True, help="Ignore information vulnerabilities")
@click.option('--hostname-resolution', is_flag=True, help="Resolve hostname")
@click.option('--vuln-tag', help="Vuln tag", default=None)
@click.option('--service-tag', help="Service tag", default=None)
@click.option('--host-tag', help="Host tag", default=None)
@click.option('--force', help="Process the output of the command regardless of the result", is_flag=True)
def process_command(command, plugin_id, custom_plugins_folder, dont_run, summary, output_file, show_output,
                    ignore_info, hostname_resolution, vuln_tag, service_tag, host_tag, force):
    plugins_manager = PluginsManager(custom_plugins_folder,
                                     ignore_info=ignore_info,
                                     hostname_resolution=hostname_resolution,
                                     vuln_tag=vuln_tag,
                                     service_tag=service_tag,
                                     host_tag=host_tag)
    analyzer = CommandAnalyzer(plugins_manager)
    if plugin_id:
        plugin = plugins_manager.get_plugin(plugin_id)
        if not plugin:
            click.echo(click.style(f"Invalid Plugin: {plugin_id}", fg="red"), err=True)
            return
    else:
        plugin = analyzer.get_plugin(command)
        if not plugin:
            click.echo(click.style(f"Failed to detect command: {command}", fg="red"), err=True)
            return
    current_path = os.path.abspath(os.getcwd())
    modified_command = plugin.processCommandString(getpass.getuser(), current_path, command)
    if modified_command:
        command = modified_command
    if dont_run:
        color_message = click.style("Command: ", fg="green")
        click.echo(f"{color_message} {command}")
    else:
        p = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE) # nosec
        output = io.StringIO()
        while True:
            retcode = p.poll()
            line = p.stdout.readline().decode('utf-8')
            if show_output:
                sys.stdout.write(line)
            output.write(line)
            if retcode is not None:
                extra_lines = map(lambda x: x.decode('utf-8'), p.stdout.readlines())
                if show_output:
                    sys.stdout.writelines(line)
                output.writelines(extra_lines)
                break
        output_value = output.getvalue()
        if retcode == 0 or force:
            plugin.processOutput(output_value)
            if summary:
                click.echo(json.dumps(plugin.get_summary(), indent=4))
            else:
                if output_file:
                    with open(output_file, "w") as f:
                        json.dump(plugin.get_data(), f)
                else:
                    click.echo(json.dumps(plugin.get_data(), indent=4))
        else:
            click.echo(click.style("Command execution error!!", fg="red"), err=True)



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
            click.echo(click.style(f"Failed to detect report: {report_file}", fg="red"), err=True)


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
        click.echo(click.style(f"Failed to detect command: {command}", fg="red"), err=True)
