"""
Faraday Penetration Test IDE - Credential Import Plugin
Copyright (C) 2026  Infobyte LLC (https://www.faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

import csv
from io import StringIO
from faraday_plugins.plugins.plugin import PluginCSVFormat

__author__ = "David Kraus"
__copyright__ = "Copyright (c) 2026, Faraday Security LLC"
__credits__ = ["David Kraus"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "David Kraus"
__email__ = "dkraus@faradaysec.com"
__status__ = "Development"

_USERNAME_COLS = {"username", "user", "login", "email", "mail", "usuario"}
_PASSWORD_COLS = {"password", "passwd", "pass", "contraseña", "clave"}
_ENDPOINT_COLS = {"endpoint", "url", "site"}
_ALL_HEADER_NAMES = _USERNAME_COLS | _PASSWORD_COLS | _ENDPOINT_COLS


def _is_header_line(line):
    """Return True if `line` looks like a CSV header row."""
    for delim in (",", "\t", ";", "|"):
        parts = [p.strip().lower() for p in line.split(delim)]
        if (len(parts) >= 2 and
                any(p in _USERNAME_COLS for p in parts) and
                any(p in _PASSWORD_COLS for p in parts)):
            return True
    # For colon-separated headers require ALL parts to be keywords and at least 3 fields
    # (2-part lines like "user:password" are indistinguishable from real credentials).
    colon_parts = [p.strip().lower() for p in line.split(":")]
    if len(colon_parts) >= 3 and all(p in _ALL_HEADER_NAMES for p in colon_parts):
        return True
    return False


class CredentialCSVPlugin(PluginCSVFormat):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = "faradaycredential_csv"
        self.name = "Faraday Credential CSV Importer"
        self.plugin_version = "1.0"
        self._schema_version = "1.0"
        self.extension = [".csv", ".txt"]
        # Match only files that have at least one username-like AND one password-like column.
        # A list of sets: detection passes if any set is a subset of the file's headers.
        self.csv_headers = [
            {u, p}
            for u in _USERNAME_COLS
            for p in _PASSWORD_COLS
        ]

    def report_belongs_to(self, report_path="", extension="", file_csv_headers=None, **kwargs):
        ext_match = (extension in self.extension) if isinstance(self.extension, list) else (extension == self.extension)
        if not ext_match:
            return False

        # Standard CSV: the manager already extracted the headers with csv.DictReader.
        if file_csv_headers:
            normalized = {h.strip().lstrip("﻿").lower() for h in file_csv_headers}
            for combo in self.csv_headers:
                if combo.issubset(normalized):
                    return True

        # Fallback: read first line directly for colon-separated or non-standard delimiters.
        if report_path:
            try:
                with open(report_path, "r", encoding="utf-8-sig", errors="ignore") as fh:
                    first_line = fh.readline().strip()
                parts = [p.strip().lstrip("﻿").lower() for p in first_line.split(":")]
                if (len(parts) >= 3 and
                        all(p in _ALL_HEADER_NAMES for p in parts) and
                        any(p in _USERNAME_COLS for p in parts) and
                        any(p in _PASSWORD_COLS for p in parts)):
                    return True
            except Exception:
                pass

        return False

    def _add_credential(self, username, password, endpoint=""):
        if "credentials" not in self.vulns_data:
            self.vulns_data["credentials"] = []
        self.vulns_data["credentials"].append({
            "username": username,
            "password": password,
            "endpoint": endpoint,
            "owned": False,
            "leak_date": None,
        })

    def parseOutputString(self, output):
        clean = output.strip().strip("'").lstrip("﻿")
        if not clean:
            self.logger.error("Empty file")
            return

        lines = [line for line in clean.splitlines() if line.strip()]
        if not lines:
            return

        if _is_header_line(lines[0]):
            self._parse_csv_with_headers(clean)
        else:
            self._parse_colon_dump(lines)

    def _parse_csv_with_headers(self, content):
        f = StringIO(content)
        try:
            dialect = csv.Sniffer().sniff(content[:2048])
            f.seek(0)
            reader = csv.DictReader(f, dialect=dialect)
            headers = [h.strip().lstrip("﻿").lower() for h in (reader.fieldnames or [])]
            reader.fieldnames = headers

            username_col = next((h for h in headers if h in _USERNAME_COLS), None)
            password_col = next((h for h in headers if h in _PASSWORD_COLS), None)
            endpoint_col = next((h for h in headers if h in _ENDPOINT_COLS), None)

            if not username_col or not password_col:
                self.logger.error(f"Cannot find username/password columns in headers: {headers}")
                return

            for row in reader:
                username = (row.get(username_col) or "").strip()
                password = (row.get(password_col) or "").strip()
                endpoint = (row.get(endpoint_col) or "").strip() if endpoint_col else ""
                if username and password:
                    self._add_credential(username, password, endpoint)
        except csv.Error as e:
            self.logger.error(f"CSV parsing error: {e}")
        except StopIteration:
            self.logger.error("Empty CSV file")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
        finally:
            f.close()

    def _parse_colon_dump(self, lines):
        """Parse colon-separated credential dumps.

        Two-field lines:  username:password
        Three-field lines: endpoint:username:password
        Lines without colons are silently skipped.
        """
        for line in lines:
            line = line.strip()
            if ":" not in line:
                continue
            parts = line.split(":", 2)
            if len(parts) == 2:
                username, password = parts[0].strip(), parts[1].strip()
                if username and password:
                    self._add_credential(username, password)
            else:
                endpoint, username, password = parts[0].strip(), parts[1].strip(), parts[2].strip()
                if username and password:
                    self._add_credential(username, password, endpoint)

    def get_summary(self):
        summary = super().get_summary()
        plugin_json = self.get_data()
        summary["credentials"] = len(plugin_json.get("credentials", []))
        return summary


def createPlugin(*args, **kwargs):
    return CredentialCSVPlugin(*args, **kwargs)
