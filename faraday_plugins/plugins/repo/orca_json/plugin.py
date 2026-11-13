"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

"""

import json

from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.repo.orca_json.mapper import OrcaFindingsMixin

__author__ = "David Kraus"
__copyright__ = "Copyright (c) 2026, Infobyte LLC"
__credits__ = ["David Kraus"]
__version__ = "1.0.0"
__maintainer__ = "David Kraus"
__email__ = "dkraus@faradaysec.com"
__status__ = "Development"


class OrcaJson(OrcaFindingsMixin, PluginJsonFormat):
    """Parses the JSON vulnerability export (Discovery) of ORCA Security."""

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "orca_json"
        self.name = "ORCA Security JSON Export Plugin"
        self.plugin_version = "1.0.0"
        self.version = "1.0.0"
        self.framework_version = "1.0.0"
        # Only keys present in every finding: Description, CvssScore, ThreatImpact... are optional.
        self.json_keys = {"Name", "CveId", "CvssSeverity", "Inventory", "InstalledPackage", "CloudAccount"}
        self._temp_file_extension = "json"

    def parseOutputString(self, output, debug=False):
        try:
            # A BOM is accepted by the analyzer (it reads bytes) but not by json.loads on a str.
            findings = json.loads(output.lstrip("﻿"))
        except ValueError:
            self.logger.error("ORCA JSON report could not be decoded")
            return
        if isinstance(findings, dict):
            findings = [findings]
        if isinstance(findings, list):
            self.process_findings(findings)


def createPlugin(*args, **kwargs):
    return OrcaJson(*args, **kwargs)
