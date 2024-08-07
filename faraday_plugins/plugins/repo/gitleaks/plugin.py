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
        self.json_keys = {
            'Description',
            'StartLine',
            'EndLine',
            'StartColumn',
            'EndColumn',
            'Match',
            'Secret',
            'File',
            'SyslinkFile',
            'Commit',
            'Entropy',
            'Author,'
            'Email',
            'Date',
            'Message',
            'Tags',
            'RuleID',
            'Fingerprint',
        }

    def parseOutputString(self, output, debug=False):
        json_output = json.loads(output)
        for leak in json_output:

            description = json.dumps({
                    'Match': leak.get('Match'),
                    'Secret': leak.get('Secret'),
                    'Commit': leak.get('Commit'),
                    'Author': leak.get('Author'),
                    'Email': leak.get('Email'),
                    'Date': leak.get('Date'),
                    'Tags': leak.get('Tags'),
                    'RuleID': leak.get('RuleID'),
                    'Fingerprint': leak.get('Fingerprint'),
                })

            host_id = self.createAndAddHost(
                name=leak.get('File'),
                hostnames=[leak.get('File')])
            self.createAndAddVulnToHost(
                host_id,
                name=leak.get('Description'),
                desc=description,
                severity='high',
                status='confirmed',
            )


def createPlugin(*args, **kwargs):
    return GitleaksPlugin(*args, **kwargs)
