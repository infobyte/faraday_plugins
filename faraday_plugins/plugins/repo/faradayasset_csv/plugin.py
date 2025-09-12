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
        self.id = "faradayasset_csv"
        self.name = "Faraday Asset CSV Importer"
        self.plugin_version = "1.0"
        self._schema_version = "1.0"
        self.csv_headers = {"asset", "description", "os", "mac_address"}

    def parseOutputString(self, output):
        clean_output = output.strip().strip("'")
        f = StringIO(clean_output)

        try:
            sample = clean_output[:1024]
            dialect = csv.Sniffer().sniff(sample)

            f.seek(0)
            reader = csv.reader(f, dialect)

            headers = next(reader)
            headers = [h.strip().lower() for h in headers]

            missing_headers = self.csv_headers - set(headers)
            if missing_headers:
                self.logger.error(
                    f"Missing required headers: {', '.join(missing_headers)}"
                )
                return

            for row in reader:
                if not any(field.strip() for field in row):
                    continue

                row_data = {
                    headers[i]: row[i].strip()
                    for i in range(min(len(headers), len(row)))
                }

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
