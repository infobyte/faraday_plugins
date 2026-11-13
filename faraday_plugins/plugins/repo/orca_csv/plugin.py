"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

"""

import csv
import io
import sys

from faraday_plugins.plugins.plugin import PluginCSVFormat
from faraday_plugins.plugins.repo.orca_json.mapper import OrcaFindingsMixin, csv_row_to_finding

__author__ = "David Kraus"
__copyright__ = "Copyright (c) 2026, Infobyte LLC"
__credits__ = ["David Kraus"]
__version__ = "1.0.0"
__maintainer__ = "David Kraus"
__email__ = "dkraus@faradaysec.com"
__status__ = "Development"


class OrcaCSV(OrcaFindingsMixin, PluginCSVFormat):
    """Parses the CSV vulnerability export (Discovery) of ORCA Security."""

    # The console export is "," separated; re-saved by a Spanish locale Excel it becomes ";".
    DELIMITERS = (",", ";")

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "orca_csv"
        self.name = "ORCA Security CSV Export Plugin"
        self.plugin_version = "1.0.0"
        self.version = "1.0.0"
        self.framework_version = "1.0.0"
        self.csv_headers = {"Name", "CveId", "CvssSeverity", "Inventory.Name", "InstalledPackage.Name"}
        self._temp_file_extension = "csv"

    def report_belongs_to(self, file_csv_headers=None, **kwargs):
        # The analyzer decodes the file as plain UTF-8, so a CSV saved with a BOM (Excel "CSV UTF-8")
        # arrives with the first column as "﻿Name".
        headers = {(header or "").lstrip("﻿") for header in file_csv_headers or set()}
        return super().report_belongs_to(file_csv_headers=headers, **kwargs)

    def parseOutputString(self, output, debug=False):
        csv.field_size_limit(sys.maxsize)
        output = output.lstrip("﻿")
        reader = csv.DictReader(io.StringIO(output), delimiter=self.detect_delimiter(output))
        if not reader.fieldnames:
            return
        self.process_findings(csv_row_to_finding(row) for row in reader)

    @classmethod
    def detect_delimiter(cls, output):
        """Column names never contain a delimiter, so the header line tells which one is used."""
        header = output.split("\n", 1)[0]
        return max(cls.DELIMITERS, key=header.count)


def createPlugin(*args, **kwargs):
    return OrcaCSV(*args, **kwargs)
