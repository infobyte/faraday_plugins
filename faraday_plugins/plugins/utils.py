from collections import defaultdict


def generate_report_summary(plugin_json):
    summary = {
        'hosts': 0,
        'services': 0,
        'hosts_vulns': 0,
        'services_vulns': 0,
        'severity_vulns': defaultdict(int)
    }
    summary['hosts'] = len(plugin_json['hosts'])
    summary['hosts_vulns'] = sum(list(map(lambda x: len(x['vulnerabilities']), plugin_json['hosts'])))
    hosts_with_services = filter(lambda x: len(x['services']) > 0, plugin_json['hosts'])
    host_services = list(map(lambda x: x['services'], hosts_with_services))
    summary['services'] = sum(map(lambda x: len(x), host_services))
    services_vulns = 0
    for host in plugin_json['hosts']:
        for vuln in host['vulnerabilities']:
            summary['severity_vulns'][vuln['severity']] += 1
    for services in host_services:
        for service in services:
            services_vulns += len(service['vulnerabilities'])
            for vuln in service['vulnerabilities']:
                summary['severity_vulns'][vuln['severity']] += 1
    summary['services_vulns'] = services_vulns
    return summary