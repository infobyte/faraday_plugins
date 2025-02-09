"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://www.faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import sys
import re
import csv
from ast import literal_eval

# Local application imports
from faraday_plugins.plugins.plugin import PluginCSVFormat


class CSVParser:
    def __init__(self, csv_output, logger):
        self.logger = logger
        self.host_data = [
            "host_description",
            "os",
            "mac",
            "hostnames",
            "host_tags"
        ]
        self.service_data = [
            "service_name",
            "service_description",
            "version",
            "service_status",
            "service_tags"
        ]
        self.vuln_data = [
            "name",
            "desc",
            "refs",
            "severity",
            "resolution",
            "data",
            "external_id",
            "confirmed",
            "status",
            "easeofresolution",
            "impact_confidentiality",
            "impact_integrity",
            "impact_availability",
            "impact_accountability",
            "policyviolations",
            "cve",
            "custom_fields",
            "website",
            "path",
            "cwe",
            "cvss2_base_score",
            "cvss2_vector_string",
            "cvss3_base_score",
            "cvss3_vector_string",
            "cvss4_base_score",
            "cvss4_vector_string",
            "request",
            "response",
            "method",
            "pname",
            "params",
            "query",
            "status_code",
            "tags"
        ]

        self.items = self.parse_csv(csv_output)

    def parse_csv(self, output):
        items = []
        csv.field_size_limit(sys.maxsize)
        reader = csv.DictReader(output, delimiter=',')
        obj_to_import = self.check_objects_to_import(reader.fieldnames)
        if not obj_to_import:
            return items

        if 'ip' in reader.fieldnames and 'target' not in reader.fieldnames:
            index = reader.fieldnames.index('ip')
            reader.fieldnames[index] = "target"
        custom_fields_names = self.get_custom_fields_names(reader.fieldnames)
        for row in reader:
            self.data = {
                'row_with_service': False,
                'row_with_vuln': False
            }
            # verify at least one field has data
            if not any(row.values()):
                self.logger.warning("Row with empty data found. Skipping...")
                continue
            self.build_host(row)
            if "service" in obj_to_import:
                if row['port'] and row['protocol']:
                    self.data['row_with_service'] = True
                    self.build_service(row)
                else:
                    self.data['row_with_service'] = False
            if "vuln" in obj_to_import:
                if row['name'] and row['desc']:
                    self.data['row_with_vuln'] = True
                    self.build_vulnerability(row, custom_fields_names)
                else:
                    self.data['row_with_service'] = False

            items.append(self.data)
        return items

    def check_objects_to_import(self, headers):
        obj_to_import = []

        # From valid_headers, Faraday will define which objects to import
        valid_headers = [
            "ip",
            "port", "protocol",
            "name", "desc", "target"
        ]

        matching_headers = set(valid_headers) & set(headers)

        if "ip" not in matching_headers and "target" not in matching_headers:
            self.logger.error("No host specified. Please, specify at least one host.")
            return None

        if "ip" in matching_headers:
            # Remove ip field to leave only target field
            matching_headers.remove("ip")
            if "target" not in matching_headers:
                matching_headers.add("target")

        obj_to_import.append('host')

        if "port" in matching_headers or "protocol" in matching_headers:
            port = True if "port" in matching_headers else False
            protocol = True if "protocol" in matching_headers else False

            if (port and not protocol) or (protocol and not port):
                self.logger.error(
                    "Missing columns in CSV file. "
                    "In order to import services, you need to add a column called port "
                    " and a column called protocol."
                )
                return None
            else:
                obj_to_import.append('service')

        if "name" in matching_headers or "desc" in matching_headers:
            vuln_name = True if "name" in matching_headers else False
            vuln_desc = True if "desc" in matching_headers else False

            if (vuln_name and not vuln_desc) or (vuln_desc and not vuln_name):
                self.logger.error(
                    "Missing columns in CSV file. "
                    "In order to import vulnerabilities, you need to add a "
                    "column called name and a column called desc."
                )
                return None
            else:
                obj_to_import.append('vuln')

        return obj_to_import

    @staticmethod
    def get_custom_fields_names(headers):
        custom_fields_names = []
        for header in headers:
            match = re.match(r"cf_(\S+)", header)
            if match:
                custom_fields_names.append(match.group(1))

        return custom_fields_names

    def build_host(self, row):
        self.data['target'] = row['target']
        for item in self.host_data:
            if item == "hostnames":
                self.data[item] = self.build_hostnames_list(row)
                continue

            if item in row:
                if item == "host_tags":
                    self.data[item] = literal_eval(row[item] if row[item] else '[]')
                else:
                    self.data[item] = row[item]
            else:
                self.data[item] = None

    def build_service(self, row):
        self.data['port'] = row['port']
        self.data['protocol'] = row['protocol']
        for item in self.service_data:
            if item in row:
                if item == 'service_status':
                    if row[item] == '':
                        # If status is not specified, set it as 'open'
                        self.data[item] = "open"
                        continue
                elif item == 'service_tags':
                    self.data[item] = literal_eval(row[item])
                    continue
                self.data[item] = row[item]
            else:
                self.data[item] = None

    def build_vulnerability(self, row, custom_fields_names):
        self.data['vuln_name'] = row['name']
        self.data['vuln_desc'] = row['desc']
        impact_dict = {
            "accountability": False,
            "confidentiality": False,
            "availability": False,
            "integrity": False,
        }

        if "web_vulnerability" in row:
            self.data['web_vulnerability'] = True if row['web_vulnerability'].capitalize() == "True" else False
        else:
            self.data['web_vulnerability'] = False

        for item in self.vuln_data:
            if item in row:
                if "impact_" in item:
                    impact = re.match(r"impact_(\w+)", item).group(1)
                    impact_dict[impact] = True if row[item].capitalize() == "True" else False
                elif item in ["refs", "policyviolations", "cve", "tags"]:
                    self.data[item] = literal_eval(row[item] if row[item] else '[]')
                elif "confirmed" in item:
                    self.data[item] = True if row[item].capitalize() == "True" else False
                else:
                    self.data[item] = row[item]
            else:
                self.data[item] = None

        self.data['impact'] = impact_dict
        self.data['custom_fields'] = self.parse_custom_fields(row, custom_fields_names)

    def build_hostnames_list(self, row):
        hostnames = []
        if "hostnames" in row:
            try:
                hostnames = literal_eval(row['hostnames'])
            except (ValueError, SyntaxError):
                self.logger.error("Hostname not valid. Faraday will set it as empty.")
        return hostnames

    @staticmethod
    def parse_vuln_impact(impact):
        impacts = [
            "accountability",
            "confidentiality",
            "availability",
            "integrity"
        ]
        for item in impacts:
            if item in impact:
                return item

    @staticmethod
    def parse_custom_fields(row, custom_fields_names):
        if not row:
            return {}
        custom_fields = {}
        for cf_name in custom_fields_names:
            cf_value = row["cf_" + cf_name]
            try:
                custom_fields[cf_name] = literal_eval(cf_value)
            except (ValueError, SyntaxError):
                custom_fields[cf_name] = cf_value

        return custom_fields


class FaradayCSVPlugin(PluginCSVFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "faraday_csv"
        self.name = "Faraday CSV Plugin"
        self.plugin_version = "1.0"
        self.csv_headers = [{'ip'}, {'target'}]

    def _parse_filename(self, filename):
        with open(filename, **self.open_options) as output:
            self.parseOutputString(output)

    def parseOutputString(self, output):
        parser = CSVParser(output, self.logger)

        for item in parser.items:
            h_id = self.createAndAddHost(
                name=item['target'],
                os=item['os'],
                hostnames=item['hostnames'],
                mac=item['mac'],
                description=item['host_description'] or "",
                tags=item['host_tags']
            )
            s_id = None
            if item['row_with_service']:
                s_id = self.createAndAddServiceToHost(
                    h_id,
                    name=item['service_name'],
                    protocol=item['protocol'],
                    ports=item['port'],
                    status=item['service_status'] or None,
                    version=item['version'],
                    description=item['service_description'],
                    tags=item['service_tags']
                )
            if item['row_with_vuln']:
                cvss2 = {
                    "base_score": item['cvss2_base_score'],
                }
                if item['cvss2_vector_string']:
                    cvss2["vector_string"]= item['cvss2_vector_string']
                cvss3 = {
                    "base_score": item['cvss3_base_score'],
                }
                if item['cvss3_vector_string']:
                    cvss3["vector_string"]= item['cvss3_vector_string']
                cvss4 = {
                    "base_score": item['cvss4_base_score'],
                }
                if item['cvss4_vector_string']:
                    cvss4["vector_string"]= item['cvss4_vector_string']

                if not item['web_vulnerability'] and not s_id:
                    self.createAndAddVulnToHost(
                        h_id,
                        name=item['vuln_name'],
                        desc=item['vuln_desc'],
                        ref=item['refs'],
                        severity=item['severity'],
                        resolution=item['resolution'],
                        data=item['data'],
                        external_id=item['external_id'],
                        confirmed=item['confirmed'],
                        status=item['status'] or "",
                        easeofresolution=item['easeofresolution'] or None,
                        impact=item['impact'],
                        policyviolations=item['policyviolations'],
                        cve=item['cve'],
                        cwe=item['cwe'],
                        cvss2=cvss2,
                        cvss3=cvss3,
                        cvss4=cvss4,
                        custom_fields=item['custom_fields'],
                        tags=item['tags']
                    )
                if not item['web_vulnerability'] and s_id:
                    self.createAndAddVulnToService(
                        h_id,
                        s_id,
                        name=item['vuln_name'],
                        desc=item['vuln_desc'],
                        ref=item['refs'],
                        severity=item['severity'],
                        resolution=item['resolution'],
                        data=item['data'],
                        external_id=item['external_id'],
                        confirmed=item['confirmed'],
                        status=item['status'] or "",
                        easeofresolution=item['easeofresolution'] or None,
                        impact=item['impact'],
                        policyviolations=item['policyviolations'],
                        cve=item['cve'],
                        cwe=item['cwe'],
                        cvss2=cvss2,
                        cvss3=cvss3,
                        cvss4=cvss4,
                        custom_fields=item['custom_fields'],
                        tags=item['tags']
                    )
                elif item['web_vulnerability']:
                    self.createAndAddVulnWebToService(
                        h_id,
                        s_id,
                        name=item['vuln_name'],
                        desc=item['vuln_desc'],
                        ref=item['refs'],
                        severity=item['severity'],
                        resolution=item['resolution'],
                        website=item['website'],
                        path=item['path'],
                        request=item['request'],
                        response=item['response'],
                        method=item['method'],
                        pname=item['pname'],
                        params=item['params'],
                        query=item['query'],
                        data=item['data'],
                        external_id=item['external_id'],
                        confirmed=item['confirmed'],
                        status=item['status'] or "",
                        easeofresolution=item['easeofresolution'] or None,
                        impact=item['impact'],
                        policyviolations=item['policyviolations'],
                        cve=item['cve'],
                        cwe=item['cwe'],
                        cvss2=cvss2,
                        cvss3=cvss3,
                        cvss4=cvss4,
                        status_code=item['status_code'] or None,
                        custom_fields=item['custom_fields'],
                        tags=item['tags']
                    )


def createPlugin(*args, **kwargs):
    return FaradayCSVPlugin(*args, **kwargs)
