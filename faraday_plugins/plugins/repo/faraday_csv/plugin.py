"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import csv
from ast import literal_eval

from faraday_plugins.plugins.plugin import PluginCSVFormat


class CSVParser:
    def __init__(self, csv_output):
        self.items = self.parse_csv(csv_output)

    def parse_csv(self, output):
        items_dict = {}
        change_headers = False
        services_id = {} # dict with a service id as key and its parent id as value 
        reader = csv.DictReader(output, delimiter=',')

        for row in reader:
            if change_headers:
                reader.fieldnames = self.set_new_headers(row)
                change_headers = False

            if not row['obj_type']:
                change_headers = True

            elif row['obj_type'] == 'host':
                # Convert string to list
                row['hostnames'] = literal_eval(row['hostnames'])
                host_id = row.pop('host_id')
                items_dict[host_id] = {
                    'host': row,
                    'services': {},
                    'vulns': [],
                }

            elif row['obj_type'] == 'service':
                parent_id = row['parent_id']
                service_id = row['service_id']
                items_dict[parent_id]['services'][service_id] = row
                services_id[service_id] = parent_id

            elif row['obj_type'] == 'vulnerability':
                # Convert string to list
                row['hostnames'] = literal_eval(row['hostnames'])
                row['comments'] = literal_eval(row['comments'])
                row['refs'] = literal_eval(row['refs'])
                row['policyviolations'] = literal_eval(row['policyviolations'])
                row['custom_fields'] = self.parse_custom_fields(row)
                row['impact'] = self.parse_vuln_impact(row)
                if row['parent_type'] == 'Host':
                    parent_id = row['parent_id']
                    items_dict[parent_id]['vulns'].append(
                        {
                            'parent_id': row['parent_id'],
                            'parent_type': row['parent_type'],
                            'data': row
                        }
                    )

                elif row['parent_type'] == 'Service':
                    host_id = services_id[row['parent_id']] # To use the correct key in items_dict
                    items_dict[host_id]['vulns'].append(
                        {
                            'parent_id': row['parent_id'],
                            'parent_type': row['parent_type'],
                            'data': row
                        }
                    )

        return items_dict

    def set_new_headers(self, row):
        new_headers = []
        for key, value in row.items():
            if key:
                new_headers.append(value)
            else:
                # If one header is longer that the other, the Key is None and the
                #  value is a list containing the remaining values of the longest header
                for item in value:
                    new_headers.append(item)

        return new_headers

    def parse_vuln_impact(self, vuln_data):
        impact = {
            "accountability":True if vuln_data['impact_accountability'] == "True" else False,
            "confidentiality":True if vuln_data['impact_confidentiality'] == "True" else False,
            "availability":True if vuln_data['impact_availability'] == "True" else False,
            "integrity":True if vuln_data['impact_integrity'] == "True" else False,
        }
        return impact

    def parse_custom_fields(self, vuln):
        custom_fields = {}
        vuln_headers = [
            "confirmed", "vuln_id", "date", "update_date", "vuln_name", "severity", "service",
            "target", "vuln_desc", "vuln_status", "hostnames", "comments",
            "vuln_owner", "os", "resolution", "refs", "easeofresolution",
            "web_vulnerability", "data", "website", "path", "status_code",
            "request", "response", "method", "params", "pname", "query",
            "policyviolations", "external_id", "impact_confidentiality",
            "impact_integrity", "impact_availability", "impact_accountability",
            "vuln_creator", "obj_type", "parent_id", "parent_type"
        ]
        # The additional fields between vuln_headers and vuln.keys() are the Custom Fields
        custom_fields_names = set(vuln.keys()).difference(vuln_headers)
        for name in custom_fields_names:
            cf_value = vuln[name]
            try:
                custom_fields[name] = literal_eval(cf_value)
            except (ValueError, SyntaxError):
                custom_fields[name] = cf_value
        return custom_fields

class FaradayCSVPlugin(PluginCSVFormat):
    def __init__(self):
        super().__init__()
        self.id = "faraday_csv"
        self.name = "Faraday CSV Plugin"
        self.plugin_version = "1.0"
        self.options = None
        self.csv_headers = {
            "host_id", "ip", "hostnames", "host_description", "os", "mac",
            "host_owned", "host_creator_id", "obj_type"
        }

    def parseOutputString(self, output, debug=False):
        parser = CSVParser(output)
        services_ids = {}
        for key, value in parser.items.items():
            host = value['host']
            h_id = self.createAndAddHost(
                name=host['ip'],
                os=host['os'],
                hostnames=host['hostnames'],
                mac=host['mac'],
                description=host['host_description']
            )

            for _id, service_data in value['services'].items():
                s_id = self.createAndAddServiceToHost(
                    h_id,
                    name=service_data['service_name'],
                    protocol=service_data['protocol'],
                    ports=service_data['port'],
                    status=service_data['service_status'],
                    version=service_data['version'],
                    description=service_data['service_description']
                )
                services_ids[service_data['service_id']] = s_id
            
            for vuln in value['vulns']:
                if vuln['parent_type'] == 'Host':
                    self.createAndAddVulnToHost(
                        h_id,
                        name=vuln['data']['vuln_name'],
                        desc=vuln['data']['vuln_desc'],
                        ref=vuln['data']['refs'],
                        severity=vuln['data']['severity'],
                        resolution=vuln['data']['resolution'],
                        data=vuln['data']['data'],
                        external_id=vuln['data']['external_id'],
                        confirmed=vuln['data']['confirmed'],
                        status=vuln['data']['vuln_status'],
                        easeofresolution=vuln['data']['easeofresolution'] or None,
                        impact=vuln['data']['impact'],
                        policyviolations=vuln['data']['policyviolations'],
                        custom_fields=vuln['data']['custom_fields']
                    )
                elif vuln['parent_type'] == 'Service':
                    service_id = services_ids[vuln['parent_id']]
                    if vuln['data']['web_vulnerability']:
                        self.createAndAddVulnWebToService(# TODO faltan campos (status_code) ademas de los de createAndAddVulnToHost
                            h_id,
                            service_id,
                            name=vuln['data']['vuln_name'],
                            desc=vuln['data']['vuln_desc'],
                            ref=vuln['data']['refs'],
                            severity=vuln['data']['severity'],
                            resolution=vuln['data']['resolution'],
                            website=vuln['data']['website'],
                            path=vuln['data']['path'],
                            request=vuln['data']['request'],
                            response=vuln['data']['response'],
                            method=vuln['data']['method'],
                            pname=vuln['data']['pname'],
                            params=vuln['data']['params'],
                            query=vuln['data']['query'],
                            data=vuln['data']['data'],
                            external_id=vuln['data']['external_id'],
                            confirmed=vuln['data']['confirmed'],
                            status=vuln['data']['vuln_status'],
                            easeofresolution=vuln['data']['easeofresolution'] or None,
                            impact=vuln['data']['impact'],
                            policyviolations=vuln['data']['policyviolations'],
                            status_code=vuln['data']['status_code'],
                            custom_fields=vuln['data']['custom_fields']
                        )
                    else:
                        self.createAndAddVulnToService(# TODO faltan campos (status_code) ademas de los de createAndAddVulnToHost
                            h_id,
                            service_id,
                            name=vuln['data']['name'],
                            desc=vuln['data']['vuln_desc'],
                            ref=vuln['data']['refs'],
                            severity=vuln['data']['severity'],
                            resolution=vuln['data']['resolution'],
                            data=vuln['data']['data'],
                            external_id=vuln['data']['external_id'],
                            confirmed=vuln['data']['confirmed'],
                            status=vuln['data']['vuln_status'],
                            easeofresolution=vuln['data']['easeofresolution'] or None,
                            impact=vuln['data']['impact'],
                            policyviolations=vuln['data']['policyviolations'],
                            custom_fields=vuln['data']['custom_fields']
                        )

def createPlugin():
    return FaradayCSVPlugin()