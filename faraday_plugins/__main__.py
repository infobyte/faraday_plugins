import logging
import os
import sys
import click

from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer

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
def list():
    plugins_manager = PluginsManager()
    click.echo("Available Plugins:")
    loaded_plugins = 0
    for plugin_id, plugin in plugins_manager.get_plugins():
        click.echo(f"{plugin.id} - {plugin.name}")
        loaded_plugins += 1
    click.echo(f"Loaded Plugins: {loaded_plugins}")


@cli.command()
@click.argument('plugin_id')
@click.argument('report_file')
def process(plugin_id, report_file):
    if not os.path.isfile(report_file):
        click.echo(f"File {report_file} Don't Exists")
    else:
        plugins_manager = PluginsManager()
        plugin = plugins_manager.get_plugin(plugin_id)
        if plugin:
            plugin.processReport(report_file)
            click.echo(plugin.get_json())
        else:
            click.echo(f"Unknown Plugin: {plugin_id}")


@cli.command()
@click.argument('report_file')
def detect(report_file):
    if not os.path.isfile(report_file):
        click.echo(f"File {report_file} Don't Exists")
    else:
        plugins_manager = PluginsManager()
        analyzer = ReportAnalyzer(plugins_manager)
        plugin = analyzer.get_plugin(report_file)
        if plugin:
            click.echo(plugin)
        else:
            click.echo(f"Failed to detect")


if __name__ == "__main__":
    cli()
