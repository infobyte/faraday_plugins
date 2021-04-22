"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""

import dateutil

from faraday_plugins.plugins.plugin import PluginXMLFormat

__author__ = "Blas"
__copyright__ = "Copyright (c) 2019, Infobyte LLC"
__credits__ = ["Blas", "Nicolas Rebagliati"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Blas"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"

from faraday_plugins.plugins.repo.nessus.nessusParser import NessusParser


class NessusPlugin(PluginXMLFormat):
    """
    Example plugin to parse nessus output.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.extension = ".nessus"
        self.identifier_tag = "NessusClientData_v2"
        self.id = "Nessus"
        self.name = "Nessus XML Output Plugin"
        self.plugin_version = "0.0.1"
        self.version = "5.2.4"
        self.framework_version = "1.0.1"
        self.options = None

    @staticmethod
    def parse_compliance_data(data: dict):
        compliance_data = {}
        for key, value in data.items():
            if 'compliance-' in key:
                compliance_name = key.split("}")[-1]
                compliance_data[compliance_name] = value
        return compliance_data

    def parseOutputString(self, output):
        """
        This method will discard the output the shell sends, it will read it from
        the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """

        try:
            parser = NessusParser(output)
        except Exception as e:
            self.logger.error(str(e))
            return None
        report_hosts = parser.report.report_hosts

        if report_hosts:
            run_date = report_hosts[-1].host_properties.host_end
            if run_date:
                run_date = dateutil.parser.parse(run_date)

            for host in report_hosts:
                properties = host.host_properties
                website = None
                mac = properties.mac_address
                os = properties.operating_system
                ip_host = properties.host_ip
                host_name = properties.host_fqdn
                if host_name:
                    website = host_name
                host_id = self.createAndAddHost(ip_host, os=os, hostnames=host_name, mac=mac)

                for items in host.report_items:
                    import ipdb;
                    ipdb.set_trace()


            for set_info, ip in enumerate(parser.report.report_json['ip'], start=1):
                website = None
                mac = parser.report.report_json['desc'][set_info - 1].get('mac-address', '')
                os = parser.report.report_json['desc'][set_info - 1].get('operating-system', None)
                ip_host = parser.report.report_json['desc'][set_info - 1].get('host-ip', ip)
                host_name = parser.report.report_json['desc'][set_info - 1].get('host-fqdn', None)
                if host_name:
                    website = host_name
                host_id = self.createAndAddHost(ip_host, os=os, hostnames=host_name, mac=mac)

                for report_item in parser.report.report_json['serv'][set_info - 1]:
                    vulnerability_name = report_item.plugin_name
                    if not vulnerability_name:
                        continue
                    item_name = report_item.svc_name
                    item_port = report_item.port
                    item_protocol = report_item.protocol
                    item_severity = report_item.severity
                    external_id = report_item.plugin_id
                    serv_description = report_item.description
                    # cve.append(report_item.plugin_output)
                    description = report_item.plugin_output
                    data = report_item.info
                    risk_factor = data.get('risk_factor', None)
                    cve = []
                    ref = []
                    if risk_factor == 'None' or risk_factor is None:
                        risk_factor = item_severity  # I checked several external id and most of them were info
                    if item_name == 'general':
                        description = data.get('description', '')
                        resolution = data.get('solution', '')
                        data_pluin_ouput = data.get('plugin_output', '')
                        if 'cvss_base_score' in data:
                            cvss_base_score = f"CVSS:{data['cvss_base_score']}"
                            ref.append(cvss_base_score)
                        policyviolations = []
                        if report_item.plugin_family == 'Policy Compliance':
                            # This condition was added to support CIS Benchmark in policy violation field.
                            bis_benchmark_data = report_item.description.split('\n')
                            compliance_data = parser.parse_compliance_data(data)
                            compliance_info = compliance_data.get('compliance-info', '')
                            if compliance_info and not description:
                                description = compliance_info
                            compliance_reference = compliance_data.get('compliance-reference', '').replace('|',
                                                                                                           ':').split(
                                ',')
                            compliance_result = compliance_data.get('compliance-result', '')
                            for reference in compliance_reference:
                                ref.append(reference)
                            compliance_check_name = compliance_data.get('compliance-check-name', '')
                            compliance_solution = compliance_data.get('compliance-solution', '')
                            if compliance_solution and not resolution:
                                resolution = compliance_solution
                            policy_item = f'{compliance_check_name} - {compliance_result}'
                            for policy_check_data in bis_benchmark_data:
                                if 'ref.' in policy_check_data:
                                    ref.append(policy_check_data)
                            if 'compliance-see-also' in compliance_data:
                                ref.append(compliance_data.get('compliance-see-also'))
                            # We used this info from tenable: https://community.tenable.com/s/article/Compliance-checks-in-SecurityCenter
                            policyviolations.append(policy_item)
                            vulnerability_name = f'{vulnerability_name}: {policy_item}'
                        self.createAndAddVulnToHost(host_id,
                                                    vulnerability_name,
                                                    desc=description,
                                                    severity=risk_factor,
                                                    resolution=resolution,
                                                    data=data_pluin_ouput,
                                                    ref=ref,
                                                    policyviolations=policyviolations,
                                                    external_id=external_id,
                                                    run_date=run_date)
                    else:
                        vulnerability_name = report_item.plugin_name
                        description = data.get('description', '')
                        resolution = data.get('solution', '')
                        data_pluin_ouput = data.get('plugin_output', '')
                        if 'cvss_base_score' in data:
                            cvss_base_score = f"CVSS:{data['cvss_base_score']}"
                            ref.append(cvss_base_score)
                        if 'cvss_vector' in data:
                            cvss_vector = f"CVSSVECTOR:{data['cvss_vector']}"
                            ref.append(cvss_vector)
                        if 'see_also' in data:
                            ref.append(data['see_also'])
                        if 'cpe' in data:
                            ref.append(data['cpe'])
                        if 'xref' in data:
                            ref.append(data['xref'])

                        service_id = self.createAndAddServiceToHost(host_id, name=item_name, protocol=item_protocol,
                                                                    ports=item_port)

                        if item_name == 'www' or item_name == 'http':
                            self.createAndAddVulnWebToService(host_id,
                                                              service_id,
                                                              name=vulnerability_name,
                                                              desc=description,
                                                              data=data_pluin_ouput,
                                                              severity=risk_factor,
                                                              resolution=resolution,
                                                              ref=ref,
                                                              external_id=external_id,
                                                              website=website,
                                                              run_date=run_date)
                        else:
                            self.createAndAddVulnToService(host_id,
                                                           service_id,
                                                           name=vulnerability_name,
                                                           severity=risk_factor,
                                                           desc=description,
                                                           ref=ref,
                                                           data=data_pluin_ouput,
                                                           external_id=external_id,
                                                           resolution=resolution,
                                                           run_date=run_date)


def createPlugin(ignore_info=False):
    return NessusPlugin(ignore_info=ignore_info)
