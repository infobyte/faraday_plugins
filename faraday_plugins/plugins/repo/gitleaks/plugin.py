"""
Faraday Plugins
Copyright (c) 2021 Faraday Security LLC (https://www.faradaysec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
from faraday_plugins.plugins.plugin import PluginJsonFormat


class GitleaksPlugin(PluginJsonFormat):
    """
    Parse gitleaks JSON output
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = 'gitleaks'
        self.name = 'Gitleaks'
        self.plugin_version = '0.1'
        self.version = '1.0.0'
        self.json_keys = {'Match', 'Secret', 'Commit', 'Author', 'Email', 'Date', 'RuleID', 'Fingerprint', 'File', 'Description'}

    def parseOutputString(self, output, debug=False):
        json_output = json.loads(output)
        for leak in json_output:

            description = f"Match: {leak.get('Match')}\n" \
                          f"Secret: {leak.get('Secret')}\n" \
                          f"Commit: {leak.get('Commit')}\n" \
                          f"Author: {leak.get('Author')}\n" \
                          f"Email: {leak.get('Email')}\n" \
                          f"Date: {leak.get('Date')}\n" \
                          f"RuleID: {leak.get('RuleID')}\n" \
                          f"Fingerprint: {leak.get('Fingerprint')}\n"

            host_id = self.createAndAddHost(
                name=leak.get('File'),
            )
            self.createAndAddVulnToHost(
                host_id,
                name=leak.get('Description'),
                desc=description,
                severity='informational',
                status='open',
            )


def createPlugin(*args, **kwargs):
    return GitleaksPlugin(*args, **kwargs)
