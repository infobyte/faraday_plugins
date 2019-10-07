import click
from .plugins.manager import PluginsManager, ReportAnalyzer


@click.group()
def cli():
    pass


@cli.command()
@click.argument('plugin_id')
@click.argument('report_file')
def process(plugin_id, report_file):
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
    plugins_manager = PluginsManager()
    analyzer = ReportAnalyzer(plugins_manager)
    plugin = analyzer.get_plugin(report_file)
    if plugin:
        click.echo(plugin)
    else:
        click.echo(f"Failed to detect")

@cli.command()
def list():
    plugins_manager = PluginsManager()
    click.echo("Available Plugins")
    for plugin_id, plugin in plugins_manager.get_plugins():
        click.echo(f"{plugin.id} - {plugin.name}")

if __name__ == "__main__":
    cli()
