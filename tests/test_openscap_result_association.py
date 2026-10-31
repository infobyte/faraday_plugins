#!/usr/bin/env python
"""Offline regression tests: OpenSCAP multi-TestResult asset association.

Synthetic XCCDF 1.2 Benchmarks (namespace http://checklists.nist.gov/xccdf/1.2)
with several TestResult elements, one target each.  Only documented IP ranges
(RFC 5737) and .example hostnames are used; MACs are locally administered.

These tests exercise the real plugin (OpenScapPlugin.parseOutputString and
PluginBase.processReport -> caches -> get_data/get_summary).  Nothing is mocked.
"""

from datetime import datetime
from pathlib import Path

import pytest

from faraday_plugins.plugins.repo.openscap.plugin import (
    OpenScapParser,
    createPlugin,
)

NS = 'http://checklists.nist.gov/xccdf/1.2'

SSG_HREF = 'ssg-example-xccdf.xml'
CHECK_SYSTEM = 'urn:xccdf:check:system:scap'


def _rule(rule_id, title, ident):
    return f'''
  <Rule id="xccdf_com.example_rule_{rule_id}" severity="high">
    <title>{title}</title>
    <ident system="https://example.com/ident">{ident}</ident>
    <check system="{CHECK_SYSTEM}">
      <check-content-ref name="{rule_id}_content" href="{SSG_HREF}"/>
    </check>
  </Rule>'''


def _rule_result(rule_id, status, time='2026-10-30T10:00:30'):
    return f'''
    <rule-result idref="xccdf_com.example_rule_{rule_id}" time="{time}" severity="high">
      <result>{status}</result>
      <check system="{CHECK_SYSTEM}">
        <check-content-ref name="{rule_id}_content" href="{SSG_HREF}"/>
      </check>
    </rule-result>'''


def _test_result(result_id, target, ip, mac, rule_results, title=None):
    title = title or f'Result for {target}'
    body = ''.join(rule_results)
    return f'''
  <TestResult id="xccdf_com.example_testresult_{result_id}" start-time="2026-10-30T10:00:00" end-time="2026-10-30T10:01:00">
    <title>{title}</title>
    <target>{target}</target>
    <target-address>{ip}</target-address>
    <target-facts>
      <fact name="urn:xccdf:fact:ethernet:MAC" type="string">{mac}</fact>
    </target-facts>{body}
    <score system="urn:xccdf:scoring:default" maximum="100">0</score>
  </TestResult>'''


def _benchmark(rules, results):
    # str input: lxml rejects an encoding declaration on unicode strings, and the
    # production parser feeds parseOutputString's argument straight to fromstring.
    return (
        f'<Benchmark xmlns="{NS}" id="xccdf_com.example_benchmark_synthetic">\n'
        '  <status date="2026-10-30">draft</status>\n'
        '  <title>Synthetic OpenSCAP benchmark for offline regression</title>'
        '  <version>1.0</version>' +
        ''.join(rules) +
        ''.join(results) +
        '\n</Benchmark>\n'
    )


RULE_A = _rule('rule-a', 'Rule A synthetic', 'RULEA')
RULE_B = _rule('rule-b', 'Rule B synthetic', 'RULEB')
RULE_C = _rule('rule-c', 'Rule C synthetic', 'RULEC')

HOST_A = ('result-a', 'host-a.example', '192.0.2.10', '02:00:00:00:00:0A')
HOST_B = ('result-b', 'host-b.example', '192.0.2.20', '02:00:00:00:00:0B')

HOST_A_IP = '192.0.2.10'
HOST_B_IP = '192.0.2.20'


def _two_host_benchmark(reverse=False, extra_results=()):
    """Host A fails rule-a, host B fails rule-c; nothing is shared."""
    results = [
        _test_result(*HOST_A, [_rule_result('rule-a', 'fail')]),
        _test_result(*HOST_B, [_rule_result('rule-c', 'fail')]),
    ]
    if reverse:
        results.reverse()
    return _benchmark([RULE_A, RULE_B, RULE_C], results + list(extra_results))


def _expected_vuln(rule_id, title):
    return {
        'name': title,
        'external_id': f'xccdf_com.example_rule_{rule_id}',
        'desc': f'name: {rule_id}_content - link: {SSG_HREF}',
        'data': CHECK_SYSTEM,
    }


def _vulns_by_host(plugin):
    """Map host ip -> ordered list of (name, external_id, desc, data)."""
    hosts = plugin.get_data()['hosts']
    mapping = {}
    for host in hosts:
        assert host['ip'] not in mapping, 'Duplicate host hidden by IP mapping'
        mapping[host['ip']] = [
            {
                'name': vuln['name'],
                'external_id': vuln['external_id'],
                'desc': vuln['desc'],
                'data': vuln['data'],
            }
            for vuln in host['vulnerabilities']
        ]
    return mapping


def _hosts_by_ip(plugin):
    hosts = plugin.get_data()['hosts']
    mapping = {host['ip']: host for host in hosts}
    assert len(mapping) == len(hosts), 'Duplicate host hidden by IP mapping'
    return mapping


@pytest.mark.parametrize('reverse', [False, True], ids=['forward', 'reversed'])
def test_two_hosts_each_report_only_its_own_failing_rule(reverse):
    plugin = createPlugin()
    plugin.parseOutputString(_two_host_benchmark(reverse=reverse))

    hosts = _hosts_by_ip(plugin)
    assert sorted(hosts) == [HOST_A_IP, HOST_B_IP]

    assert hosts[HOST_A_IP]['hostnames'] == ['host-a.example']
    assert hosts[HOST_B_IP]['hostnames'] == ['host-b.example']

    assert _vulns_by_host(plugin) == {
        HOST_A_IP: [_expected_vuln('rule-a', 'Rule A synthetic')],
        HOST_B_IP: [_expected_vuln('rule-c', 'Rule C synthetic')],
    }


def test_same_failing_rule_on_two_hosts_is_kept_for_each_host():
    xml = _benchmark(
        [RULE_A],
        [
            _test_result(*HOST_A, [_rule_result('rule-a', 'fail')]),
            _test_result(*HOST_B, [_rule_result('rule-a', 'fail')]),
        ],
    )
    plugin = createPlugin()
    plugin.parseOutputString(xml)

    assert _vulns_by_host(plugin) == {
        HOST_A_IP: [_expected_vuln('rule-a', 'Rule A synthetic')],
        HOST_B_IP: [_expected_vuln('rule-a', 'Rule A synthetic')],
    }


def test_only_failed_rules_are_attached_to_their_own_host():
    xml = _benchmark(
        [RULE_A, RULE_B, RULE_C],
        [
            _test_result(
                *HOST_A,
                [_rule_result('rule-a', 'fail'), _rule_result('rule-b', 'pass')],
            ),
            _test_result(
                *HOST_B,
                [_rule_result('rule-c', 'fail'), _rule_result('rule-b', 'notapplicable')],
            ),
        ],
    )
    plugin = createPlugin()
    plugin.parseOutputString(xml)

    assert _vulns_by_host(plugin) == {
        HOST_A_IP: [_expected_vuln('rule-a', 'Rule A synthetic')],
        HOST_B_IP: [_expected_vuln('rule-c', 'Rule C synthetic')],
    }


def test_parser_result_collections_are_owned_per_test_result():
    parser = OpenScapParser(
        _benchmark(
            [RULE_A, RULE_C],
            [
                _test_result(*HOST_A, [_rule_result('rule-a', 'fail')]),
                _test_result(*HOST_B, [_rule_result('rule-c', 'fail')]),
            ],
        )
    )

    first, second = parser.result_data
    assert first['target'] == 'host-a.example'
    assert second['target'] == 'host-b.example'

    assert first['ips'] == [HOST_A_IP]
    assert second['ips'] == [HOST_B_IP]
    assert first['mac'] == ['02:00:00:00:00:0A']
    assert second['mac'] == ['02:00:00:00:00:0B']
    assert first['ips'] is not second['ips']
    assert first['mac'] is not second['mac']
    assert first['rule_result'] is not second['rule_result']

    assert [rule['id'] for rule in first['rule_result']] == ['xccdf_com.example_rule_rule-a']
    assert [rule['id'] for rule in second['rule_result']] == ['xccdf_com.example_rule_rule-c']


def test_process_report_multi_target_populates_caches_and_summary(tmp_path):
    report = tmp_path / 'synthetic-multi-target.xml'
    report.write_text(_two_host_benchmark(), encoding='utf-8')

    plugin = createPlugin()
    plugin.processReport(Path(report))

    data = plugin.get_data()
    assert data['command']['params'] == report.name
    assert sorted(host['ip'] for host in data['hosts']) == [HOST_A_IP, HOST_B_IP]
    assert _vulns_by_host(plugin) == {
        HOST_A_IP: [_expected_vuln('rule-a', 'Rule A synthetic')],
        HOST_B_IP: [_expected_vuln('rule-c', 'Rule C synthetic')],
    }

    summary = plugin.get_summary()
    assert summary['hosts'] == 2
    assert summary['hosts_vulns'] == 2


# --- isolated controls: these describe behaviour the current code already has ---


def _single_host_benchmark():
    return _benchmark(
        [RULE_A],
        [_test_result(*HOST_A, [_rule_result('rule-a', 'fail')])],
    )


def test_control_single_result_parse_output_string_shape():
    plugin = createPlugin()
    plugin.parseOutputString(_single_host_benchmark())

    hosts = _hosts_by_ip(plugin)
    assert list(hosts) == [HOST_A_IP]
    host = hosts[HOST_A_IP]
    assert host['hostnames'] == ['host-a.example']
    assert host['mac'] == '02:00:00:00:00:0A'
    assert host['os'] == 'unknown'
    assert host['description'] == (
        'Title: Result for host-a.example Ips: [] Macs: []'
    )
    assert len(host['vulnerabilities']) == 1
    vuln = host['vulnerabilities'][0]
    assert vuln['name'] == 'Rule A synthetic'
    assert vuln['external_id'] == 'xccdf_com.example_rule_rule-a'
    assert vuln['desc'] == f'name: rule-a_content - link: {SSG_HREF}'
    assert vuln['data'] == CHECK_SYSTEM
    assert vuln['status'] == 'open'
    assert vuln['severity'] == 'high'
    assert vuln['run_date'] == datetime(2026, 10, 30, 10, 0, 30).timestamp()


def test_control_single_result_process_report_summary(tmp_path):
    report = tmp_path / 'synthetic-single-target.xml'
    report.write_text(_single_host_benchmark(), encoding='utf-8')

    plugin = createPlugin()
    plugin.processReport(Path(report))
    summary = plugin.get_summary()

    assert summary['hosts'] == 1
    assert summary['hosts_vulns'] == 1
    assert len(summary['vuln_hashes']) == 1


@pytest.mark.parametrize('reverse', [False, True], ids=['passing-first', 'passing-last'])
def test_result_without_failures_does_not_receive_other_host_failures(reverse):
    results = [
        _test_result(*HOST_A, [_rule_result('rule-a', 'pass')]),
        _test_result(*HOST_B, [_rule_result('rule-a', 'fail')]),
    ]
    if reverse:
        results.reverse()
    plugin = createPlugin()
    plugin.parseOutputString(_benchmark([RULE_A], results))

    assert _vulns_by_host(plugin) == {
        HOST_A_IP: [],
        HOST_B_IP: [_expected_vuln('rule-a', 'Rule A synthetic')],
    }
    hosts = _hosts_by_ip(plugin)
    assert hosts[HOST_A_IP]['mac'] == HOST_A[3]
    assert hosts[HOST_B_IP]['mac'] == HOST_B[3]
    assert plugin.get_summary()['hosts_vulns'] == 1


def test_repeated_target_uses_existing_host_and_vulnerability_caches():
    alias = ('result-alias', 'alias-a.example', HOST_A_IP, HOST_A[3])
    repeat = ('result-repeat', HOST_A[1], HOST_A_IP, HOST_A[3])
    xml = _benchmark(
        [RULE_A, RULE_C],
        [
            _test_result(*HOST_A, [_rule_result('rule-a', 'fail')]),
            _test_result(*alias, [_rule_result('rule-c', 'fail')]),
            _test_result(*repeat, [_rule_result('rule-a', 'fail')]),
        ],
    )
    plugin = createPlugin()
    plugin.parseOutputString(xml)

    hosts = _hosts_by_ip(plugin)
    assert list(hosts) == [HOST_A_IP]
    assert set(hosts[HOST_A_IP]['hostnames']) == {'host-a.example', 'alias-a.example'}
    assert _vulns_by_host(plugin) == {
        HOST_A_IP: [
            _expected_vuln('rule-a', 'Rule A synthetic'),
            _expected_vuln('rule-c', 'Rule C synthetic'),
        ],
    }
    summary = plugin.get_summary()
    assert summary['hosts'] == 1
    assert summary['hosts_vulns'] == 2
    assert len(summary['vuln_hashes']) == 2
