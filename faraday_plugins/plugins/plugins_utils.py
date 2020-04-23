"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import os
import logging
import socket
from collections import defaultdict

from urllib.parse import urlsplit


SERVICE_MAPPER = None

logger = logging.getLogger(__name__)


def get_vulnweb_url_fields(url):
    """Given a URL, return kwargs to pass to createAndAddVulnWebToService."""
    parse = urlsplit(url)
    return {
        "website": "{}://{}".format(parse.scheme, parse.netloc),
        "path": parse.path,
        "query": parse.query
        }

def filter_services():
    global SERVICE_MAPPER
    if not SERVICE_MAPPER:
        logger.debug("Load service mappers")
        filename = os.path.join(os.path.dirname(__file__), "port_mapper.txt")
        with open(filename, encoding='utf-8') as fp:
            SERVICE_MAPPER = list(map(lambda x: x.strip().split('\t'), list(filter(len, fp.readlines()))))
    return SERVICE_MAPPER


def get_all_protocols():
    protocols = [
        'ip',
        'tcp',
        'udp',
        'icmp',
        'sctp',
        'hopopt',
        'igmp',
        'ggp',
        'ip-encap',
        'st',
        'egp',
        'igp',
        'pup',
        'hmp',
        'xns-idp',
        'rdp',
        'iso-tp4',
        'dccp',
        'xtp',
        'ddp',
        'idpr-cmtp',
        'ipv6',
        'ipv6-route',
        'ipv6-frag',
        'idrp',
        'rsvp',
        'gre',
        'ipsec-esp',
        'ipsec-ah',
        'skip',
        'ipv6-icmp',
        'ipv6-nonxt',
        'ipv6-opts',
        'rspf cphb',
        'vmtp',
        'eigrp',
        'ospfigp',
        'ax.25',
        'ipip',
        'etherip',
        'encap',
        'pim',
        'ipcomp',
        'vrrp',
        'l2tp',
        'isis',
        'fc',
        'udplite',
        'mpls-in-ip',
        'hip',
        'shim6',
        'wesp',
        'rohc',
        'mobility-header'
    ]

    for item in protocols:
        yield item


def get_report_summary(plugin_json):
    summary = {'hosts': len(plugin_json['hosts']), 'services': 0,
               'hosts_vulns': sum(list(map(lambda x: len(x['vulnerabilities']), plugin_json['hosts']))),
               'services_vulns': 0, 'severity_vulns': defaultdict(int)}

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


def resolve_hostname(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception as e:
        return hostname
    else:
        return ip_address