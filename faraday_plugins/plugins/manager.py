import csv
import json
import logging
import os
import pkgutil
import re
import sys
import traceback
import xml.etree.ElementTree as ET
import zipfile
from importlib import import_module
from importlib.machinery import SourceFileLoader
from io import StringIO

from . import repo

logger = logging.getLogger("faraday").getChild(__name__)


class ReportAnalyzer:

    def __init__(self, plugin_manager):
        self.plugin_manager = plugin_manager

    def get_plugin(self, report_path):
        plugin = None
        if not os.path.isfile(report_path):
            logger.error("Report [%s] don't exists", report_path)
            return plugin
        else:
            file_name = os.path.basename(report_path)
            plugin = self._get_plugin_by_name(file_name)
            if not plugin:  # Was unable to detect plugin from report file name
                logger.debug("Plugin by name not found")
                plugin = self._get_plugin_by_file_type(report_path)
                if not plugin:
                    logger.debug("Plugin by file not found")
        if not plugin:
            logger.debug("Plugin for file (%s) not found", report_path)
        return plugin

    def _get_plugin_by_name(self, file_name_base):
        plugin_id = None
        plugin_name_regex = r".*_faraday_(?P<plugin_name>.+)\..*$"
        match = re.match(plugin_name_regex, file_name_base)
        if match:
            plugin_id = match.groupdict()['plugin_name'].lower()
            logger.debug("Plugin name match: %s", plugin_id)
            plugin = self.plugin_manager.get_plugin(plugin_id)
            if plugin:
                logger.debug("Plugin by name Found: %s", plugin.id)
                return plugin
            else:
                logger.debug("Invalid plugin from file name: %s", plugin_id)
                return None
        else:
            logger.debug("Could not extract plugin_id from filename: %s", file_name_base)
            return plugin_id

    def _get_plugin_by_file_type(self, report_path):
        plugin = None
        file_name = os.path.basename(report_path)
        file_name_base, file_extension = os.path.splitext(file_name)
        file_extension = file_extension.lower()
        main_tag = None
        main_tag_attributes = {}
        file_csv_headers = set()
        file_json_keys = set()
        files_in_zip = set()
        logger.debug("Analyze report File")
        # Try to parse as xml
        try:
            report_file = open(report_path, "rb")
        except Exception as e:
            logger.error("Error reading report content [%s]", e)
        else:
            try:
                for event, elem in ET.iterparse(report_file, ('start',)):
                    prefix, has_namespace, postfix = elem.tag.partition("}")
                    if has_namespace:
                        main_tag = postfix
                    else:
                        main_tag = elem.tag
                        try:
                            main_tag_attributes = elem.attrib
                        except AttributeError:
                            pass
                    break
                logger.debug("Found XML content on file: %s - Main tag: %s Attributes: %s", report_path, main_tag,
                             main_tag_attributes)
            except Exception as e:
                logger.debug("Non XML content [%s] - %s", report_path, e)
                try:
                    report_file.seek(0)
                    json_data = json.load(report_file)
                    if isinstance(json_data, list):
                        if len(json_data) > 0:
                            file_json_keys = set(json_data[0].keys())
                    else:
                        file_json_keys = set(json_data.keys())
                    logger.debug("Found JSON content on file: %s - Keys: %s", report_path, file_json_keys)
                except Exception as e:
                    logger.debug("Non JSON content [%s] - %s", report_path, e)
                    try:
                        report_file.seek(0)
                        reader_file_string = StringIO(report_file.read().decode('utf-8'))
                        reader = csv.DictReader(reader_file_string)
                        file_csv_headers = set(reader.fieldnames)
                        logger.debug("Found CSV content on file: %s - Keys: %s", report_path, file_json_keys)
                    except Exception as e:
                        logger.debug("Non CSV content [%s] - %s", report_path, e)
                        try:
                            file_zip = zipfile.ZipFile(report_path, "r")
                            files_in_zip = set(file_zip.namelist())
                            logger.debug("List of files found in ZIP %s", file_zip)
                        except Exception as e:
                            logger.debug("Non ZIP content [%s] - %s", report_path, e)
            finally:
                report_file.close()
                for _plugin_id, _plugin in self.plugin_manager.get_plugins():
                    logger.debug("Try plugin: %s", _plugin_id)
                    try:
                        if _plugin.report_belongs_to(main_tag=main_tag, main_tag_attributes=main_tag_attributes,
                                                     report_path=report_path, extension=file_extension,
                                                     file_json_keys=file_json_keys, file_csv_headers=file_csv_headers,
                                                     files_in_zip=files_in_zip):
                            plugin = _plugin
                            logger.debug("Plugin by File Found: %s", plugin.id)
                            break
                    except Exception as e:
                        logger.error("Error in plugin analysis: (%s) %s", _plugin_id, e)
        return plugin


class CommandAnalyzer:

    def __init__(self, plugin_manager):
        self.plugin_manager = plugin_manager

    def get_plugin(self, command_string):
        plugin = None
        logger.debug("Look plugin for command: %s", command_string)
        for _plugin_id, _plugin in self.plugin_manager.get_plugins():
            logger.debug("Try plugin: %s", _plugin_id)
            try:
                if _plugin.canParseCommandString(command_string):
                    plugin = _plugin
            except Exception as e:
                logger.error("Error in plugin analysis: (%s) %s", _plugin_id, e)
        return plugin


class PluginsManager:

    def __init__(self, custom_plugins_folder=None, **kwargs):
        self.kwargs = kwargs
        self.plugins = {}
        self.plugin_modules = {}
        self._load_plugins(custom_plugins_folder)

    def _load_plugins(self, custom_plugins_folder):
        logger.info("Loading Native Plugins...")
        if not self.plugins:
            for _, name, _ in filter(lambda x: x[2], pkgutil.iter_modules(repo.__path__)):
                try:
                    plugin_module = import_module(f"faraday_plugins.plugins.repo.{name}.plugin")
                    if hasattr(plugin_module, "createPlugin"):
                        plugin_instance = plugin_module.createPlugin()
                        plugin_id = plugin_instance.id.lower()
                        if not plugin_instance.auto_load:
                            logger.debug("Skip load plugin [%s]", plugin_id)
                            continue
                        if plugin_id not in self.plugin_modules:
                            self.plugin_modules[plugin_id] = plugin_module
                            logger.debug("Load Plugin [%s]", name)
                        else:
                            logger.debug("Plugin already loaded [%s]", plugin_id)
                    else:
                        logger.error("Invalid Plugin [%s]", name)
                except Exception as e:
                    logger.error("Cant load plugin module: %s [%s]", name, e)
            if custom_plugins_folder:
                if os.path.isdir(custom_plugins_folder):
                    logger.info("Loading Custom Plugins...")
                    dir_name_regexp = re.compile(r"^[\d\w\-\_]+$")
                    for name in os.listdir(custom_plugins_folder):
                        if dir_name_regexp.match(name) and name != "__pycache__":
                            module_path = os.path.join(custom_plugins_folder, name)
                            module_filename = os.path.join(module_path, "plugin.py")
                            try:
                                sys.path.append(module_path)
                                file_ext = os.path.splitext(module_filename)[1]
                                if file_ext.lower() == '.py':
                                    if name not in self.plugin_modules:
                                        loader = SourceFileLoader(name, module_filename)
                                        plugin_module = loader.load_module()
                                        plugin_instance = plugin_module.createPlugin()
                                        plugin_id = plugin_instance.id.lower()
                                        if not plugin_instance.auto_load:
                                            logger.info("Skip load plugin [%s]", plugin_id)
                                            continue
                                        if plugin_id not in self.plugin_modules:
                                            self.plugin_modules[plugin_id] = plugin_module
                                    else:
                                        logger.debug("Plugin with same name already loaded [%s]", name)
                                logger.debug("Load Plugin [%s]", name)
                            except Exception as e:
                                logger.debug("An error ocurred while loading plugin %s.\n%s", module_filename,
                                             traceback.format_exc())
                                logger.warning(e)
                else:
                    logger.warning("Invalid custom plugins folder [%s]", custom_plugins_folder)
            logger.info("%s plugins loaded", len(self.plugin_modules))

    def get_plugin(self, plugin_id):
        plugin = None
        plugin_id = plugin_id.lower()
        if plugin_id in self.plugin_modules:
            plugin = self.plugin_modules[plugin_id].createPlugin(**self.kwargs)
        else:
            logger.debug("Unknown Plugin: %s", plugin_id)
        return plugin

    def get_plugins(self):
        for plugin_id, plugin_module in self.plugin_modules.items():
            logger.debug("Instance Plugin: %s", plugin_id)
            yield plugin_id, plugin_module.createPlugin(**self.kwargs)
