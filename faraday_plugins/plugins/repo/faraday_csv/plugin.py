"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import json;
import csv

from faraday_plugins.plugins.plugin import PluginByExtension, PluginCSVFormat


class CSVParser:
    def __init__(self, csv_output):
        self.items = self.parse_csv(csv_output)

    def parse_csv(self, output):
        """"
            {
                host_id: {
                    host: [],
                    services: {},
                    vulns:[]
                }
            }
        """
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
                # Convert string to list and set the right JSON quoting
                row['hostnames'] = json.loads(row['hostnames'].replace("\'", "\""))
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
                # Convert string to list and set the right JSON quoting 
                row['hostnames'] = json.loads(row['hostnames'].replace("\'", "\""))
                row['comments'] = json.loads(row['comments'].replace("\'", "\""))
                row['refs'] = json.loads(row['refs'].replace("\'", "\""))
                row['policyviolations'] = json.loads(row['policyviolations'].replace("\'", "\""))

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

        print(json.dumps(items_dict, sort_keys=True, indent=4))
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


class FaradayCSVPlugin(PluginCSVFormat):
    def __init__(self):
        super().__init__()
        self.id = "faraday_csv"
        self.name = "Faraday CSV Plugin"
        self.plugin_version = "1.0"
        self.options = None
        self.csv_headers = {
        "confirmed", "id", "date", "name", "severity", "service",
        "target", "desc", "status", "hostnames", "comments", "owner", "os", "resolution", "easeofresolution", "web_vulnerability",
        "data", "website", "path", "status_code", "request", "method", "params", "pname", "query",
        "policyviolations", "external_id", "impact_confidentiality", "impact_integrity", "impact_availability",
        "impact_accountability", "obj_type", "parent_id", "parent_type"}

    def parseOutputString(self, output, debug=False):
        parser = CSVParser(output)
        services_ids = {}
        for key, value in parser.items.items():
            host = value['host']
            h_id = self.createAndAddHost(# TODO faltan campos (desc, owned, creator_id)
                name=host['ip'],
                os=host['os'],
                hostnames=host['hostnames'],
                mac=host['mac'],
            )

            for _id, service_data in value['services'].items():
                s_id = self.createAndAddServiceToHost(# TODO faltan campos (owned, creator_id)
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
                import pdb; pdb.set_trace()
                if vuln['parent_type'] == 'Host':
                    self.createAndAddVulnToHost(# TODO faltan campos (confirmed, target, status, comments, owner,ease, policy, impact, creator, custom fields 
                        h_id,
                        name=vuln['data']['vuln_name'],
                        desc="Testing",
                        ref=vuln['data']['refs'],
                        severity=vuln['data']['severity'],
                        resolution=vuln['data']['resolution'],
                        data=vuln['data']['data'],
                        external_id=vuln['data']['external_id']
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
                            external_id=vuln['data']['external_id']
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
                            external_id=vuln['data']['external_id']
                        )

def createPlugin():
    return FaradayCSVPlugin()