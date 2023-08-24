"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from faraday_plugins.plugins.plugin import PluginJsonFormat
from json import loads

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"


class TerraformPlugin(PluginJsonFormat):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = "TerraformPluginJson"
        self.name = "Terraform Plugin JSON Output Plugin"
        self.plugin_version = "1"
        self.version = "1"
        self.json_keys = {'results'}
        self.framework_version = "1.0.0"
        self._temp_file_extension = "json"

    def parseOutputString(self, output):
        report = loads(output)
        if isinstance(report.get('results'), list):
            self.id = "TFsecPlugin_Json"
            self.name = "TFsec Plugin JSON Output Plugin"
            for result in report.get('results'):
                host_id = self.createAndAddHost(result.get('location', {}).get("filename", "No filename"))
                data = f"Rule Provider: {result.get('rule_provider')}\n"\
                       f"Rule Service: {result.get('rule_service')}\n"\
                       f"Rule Impact: {result.get('impact')}\n"\
                       f"Long Id: {result.get('long_id')}\n" \
                       f"Line Start/End: {result.get('location').get('start_line')}"\
                       f"/{result.get('location').get('end_line')}"
                self.createAndAddVulnToHost(
                    host_id,
                    name=result.get('rule_description')[:50],
                    desc=result.get('rule_description'),
                    severity=result.get('severity','').lower(),
                    data=data,
                    external_id=result.get('rule_id'),
                    ref=result.get('links'),
                    resolution=result.get('resolution')
                )
        else:
            self.id = "TerrascanPlugin_Json"
            self.name = "Terrascan Plugin JSON Output Plugin"
            for violation in report.get('results', {}).get("violations"):
                host_id = self.createAndAddHost(violation.get('file'), description=violation.get('resource_name'))
                data = f"Category: {violation.get('category', '')}\n"\
                       f"Resource Type: {violation.get('resource_type', '')}\n"\
                       f"Line: {violation.get('line', 0)}"
                self.createAndAddVulnToHost(
                    host_id,
                    name=violation.get('rule_name'),
                    desc=violation.get('description'),
                    severity=violation.get('severity','').lower(),
                    data=data,
                    external_id=violation.get('rule_id')
                )


def createPlugin(*args, **kwargs):
    return TerraformPlugin(*args, **kwargs)
