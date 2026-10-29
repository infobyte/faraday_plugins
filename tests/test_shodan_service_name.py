import json

import pytest

from faraday_plugins.plugins.repo.shodan.plugin import ShodanPlugin


_UNSET = object()


def _record(*, ip="192.0.2.10", port=80, transport="tcp", module=_UNSET, vulns=None):
    record = {
        "ip_str": ip,
        "port": port,
        "transport": transport,
        "hostnames": [],
    }
    if module is not _UNSET:
        record["_shodan"] = {"module": module}
    if vulns is not None:
        record["vulns"] = vulns
    return record


def _parse(*records):
    plugin = ShodanPlugin()
    plugin.parseOutputString("\n".join(json.dumps(record) for record in records))
    return plugin.get_data()["hosts"]


@pytest.mark.parametrize(
    "module,transport,port,expected",
    [
        ("ssh", "tcp", 22, "ssh"),
        ("dns/udp", "udp", 53, "dns/udp"),
        ("http", "tcp", 80, "http"),
        ("http-simple-new", "tcp", 8080, "http-simple-new"),
        ("https-simple-new", "tcp", 443, "https-simple-new"),
        ("  ssh  ", "tcp", 22, "ssh"),
    ],
)
def test_service_name_uses_module_as_is(module, transport, port, expected):
    host = _parse(_record(module=module, transport=transport, port=port))[0]

    assert len(host["services"]) == 1
    service = host["services"][0]
    assert service["name"] == expected
    assert service["protocol"] == transport
    assert service["port"] == port


@pytest.mark.parametrize(
    "shodan",
    [
        _UNSET,
        None,
        {},
        [],
        "not-a-dict",
        {"module": None},
        {"module": ""},
        {"module": "   "},
        {"module": 123},
    ],
)
def test_unusable_module_falls_back_to_unknown(shodan):
    record = _record()
    if shodan is not _UNSET:
        record["_shodan"] = shodan

    host = _parse(record)[0]

    assert len(host["services"]) == 1
    assert host["services"][0]["name"] == "unknown"


@pytest.mark.parametrize("port", [22, 443])
def test_does_not_guess_service_from_port(port):
    host = _parse(_record(port=port))[0]

    assert len(host["services"]) == 1
    assert host["services"][0]["name"] == "unknown"


def test_same_host_different_ports_keeps_two_services():
    hosts = _parse(
        _record(ip="192.0.2.20", port=22, transport="tcp", module="ssh"),
        _record(ip="192.0.2.20", port=80, transport="tcp", module="http"),
    )

    assert len(hosts) == 1
    services = hosts[0]["services"]
    assert len(services) == 2
    assert {(service["name"], service["port"]) for service in services} == {
        ("ssh", 22),
        ("http", 80),
    }


def test_different_hosts_do_not_cross_service_data():
    hosts = _parse(
        _record(ip="192.0.2.30", port=22, module="ssh"),
        _record(ip="192.0.2.31", port=80, module="http"),
    )

    assert len(hosts) == 2
    by_ip = {host["ip"]: host["services"][0]["name"] for host in hosts}
    assert by_ip == {"192.0.2.30": "ssh", "192.0.2.31": "http"}


def test_same_host_port_protocol_still_deduplicates():
    hosts = _parse(
        _record(ip="192.0.2.40", port=22, transport="tcp", module="ssh"),
        _record(ip="192.0.2.40", port=22, transport="tcp", module="ssh"),
    )

    assert len(hosts) == 1
    assert len(hosts[0]["services"]) == 1
    assert hosts[0]["services"][0]["name"] == "ssh"


def test_vuln_summary_references_and_cve_are_preserved():
    hosts = _parse(
        _record(
            ip="192.0.2.50",
            port=22,
            module="ssh",
            vulns={
                "CVE-2024-1234": {
                    "summary": "Example summary",
                    "references": ["https://example.test/CVE-2024-1234"],
                }
            },
        )
    )

    assert len(hosts) == 1
    service = hosts[0]["services"][0]
    assert service["name"] == "ssh"
    assert len(service["vulnerabilities"]) == 1
    vuln = service["vulnerabilities"][0]
    assert vuln["name"] == "CVE-2024-1234"
    assert vuln["desc"] == "Example summary"
    assert vuln["refs"] == [{"name": "https://example.test/CVE-2024-1234", "type": "other"}]
    assert vuln["cve"] == ["CVE-2024-1234"]
