import json
import pytest
from faraday_plugins.plugins.manager import PluginsManager, CommandAnalyzer
from faraday_plugins.plugins.plugin import PluginBase


plugins_manager = PluginsManager()
analyzer = CommandAnalyzer(plugins_manager)

COMMANDS_FILE = './tests/commands.json'

def list_commands():
    with open(COMMANDS_FILE) as f:
        commands_dict = json.load(f)
    for command_data in commands_dict["commands"]:
        yield command_data


@pytest.mark.parametrize("command_data", list_commands())
def test_autodetected_on_commands(command_data):
    plugin_id = command_data["plugin_id"]
    command_string = command_data["command"]
    command_result = command_data["command_result"]

    plugin: PluginBase = analyzer.get_plugin(command_string)
    assert plugin, command_string
    assert plugin.id.lower() == plugin_id.lower()
    assert plugin.command.lower() == command_result.lower()

