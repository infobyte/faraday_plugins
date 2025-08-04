"""
Faraday Penetration Test IDE - Asset Import Plugin
Copyright (C) 2024  Infobyte LLC (https://www.faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

import csv
from io import StringIO
from faraday_plugins.plugins.plugin import PluginCSVFormat


class AssetCSVPlugin(PluginCSVFormat):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = "asset_csv"
        self.name = "Asset CSV Importer"
        self.plugin_version = "1.0"
        self._schema_version = "1.0"
        self.required_headers = {"asset", "description", "os", "mac_address"}

    def parseOutputString(self, output):
        # Clean the input string by removing outer quotes and extra whitespace
        clean_output = output.strip().strip("'")

        # Create a file-like object from the cleaned string
        f = StringIO(clean_output)

        try:
            # Detect CSV dialect (delimiter, quoting, etc)
            sample = clean_output[:1024]  # First 1KB for dialect detection
            dialect = csv.Sniffer().sniff(sample)

            # Reset file pointer and create reader
            f.seek(0)
            reader = csv.reader(f, dialect)

            # Read headers and validate
            headers = next(reader)
            headers = [h.strip().lower() for h in headers]

            # Validate required headers
            missing_headers = self.required_headers - set(headers)
            if missing_headers:
                self.logger.error(
                    f"Missing required headers: {', '.join(missing_headers)}"
                )
                return

            # Process each row
            for row in reader:
                # Skip empty rows
                if not any(field.strip() for field in row):
                    continue

                # Map columns to values
                row_data = {
                    headers[i]: row[i].strip()
                    for i in range(min(len(headers), len(row)))
                }

                # Create host with collected data
                self.createAndAddHost(
                    name=row_data["asset"],
                    description=row_data.get("description", ""),
                    os=row_data.get("os", ""),
                    mac=row_data.get("mac_address", ""),
                )

        except csv.Error as e:
            self.logger.error(f"CSV parsing error: {str(e)}")
        except StopIteration:
            self.logger.error("Empty CSV file")
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
        finally:
            f.close()


def createPlugin(*args, **kwargs):
    return AssetCSVPlugin(*args, **kwargs)
