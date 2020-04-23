import logging
import os
import sys
import json
import click
import colorama

from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer

colorama.init(autoreset=True)

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
        click.echo(f"{plugin.id} - {plugin.name}")
        loaded_plugins += 1
    click.echo(f"Loaded Plugins: {loaded_plugins}")



@cli.command()
@click.argument('plugin_id')
@click.argument('report_file')
@click.option('-cpf', '--custom-plugins-folder', type=str)
def process(plugin_id, report_file, custom_plugins_folder):
    if not os.path.isfile(report_file):
        click.echo(f"{colorama.Fore.RED}File {report_file} Don't Exists")
    else:
        plugins_manager = PluginsManager(custom_plugins_folder)
        plugin = plugins_manager.get_plugin(plugin_id)
        if plugin:
            plugin.processReport(report_file)
            click.echo(plugin.get_json())
        else:
            click.echo(f"{colorama.Fore.YELLOW}Unknown Plugin: {plugin_id}")


@cli.command()
@click.argument('report_file')
@click.option('-cpf', '--custom-plugins-folder', type=str)
def detect(report_file, custom_plugins_folder):
    if not os.path.isfile(report_file):
        click.echo(f"{colorama.Fore.RED}File {report_file} Don't Exists")
    else:
        plugins_manager = PluginsManager(custom_plugins_folder)
        analyzer = ReportAnalyzer(plugins_manager)
        plugin = analyzer.get_plugin(report_file)
        if plugin:
            click.echo(plugin)
        else:
            click.echo(f"{colorama.Fore.RED}Failed to detect")

@cli.command()
@click.argument('plugin_id')
@click.argument('report_file')
@click.option('-cpf', '--custom-plugins-folder', type=str)
def get_summary(plugin_id, report_file, custom_plugins_folder):
    if not os.path.isfile(report_file):
        click.echo(f"{colorama.Fore.RED}File {report_file} Don't Exists")
    else:
        plugins_manager = PluginsManager(custom_plugins_folder)
        plugin = plugins_manager.get_plugin(plugin_id)
        if plugin:
            plugin.processReport(report_file)
            click.echo(f"Report Summary for file [{plugin.id}]: {report_file}")
            click.echo(json.dumps(plugin.get_summary(), indent=4))
        else:
            click.echo(f"{colorama.Fore.YELLOW}Unknown Plugin: {plugin_id}")


if __name__ == "__main__":
    cli()
