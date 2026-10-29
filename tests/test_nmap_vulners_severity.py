"""Focused regression tests for Nmap vulners CVSS severity handling.

The XML fixtures are synthetic and contain only TEST-NET addresses. They mirror
the documented vulners.nse XML shape but are not real scanner output.
"""

from xml.etree import ElementTree as ET

import pytest

from faraday_plugins.plugins.repo.nmap.plugin import NmapPlugin

MISSING = object()

SCORE_CASES = [
    ("0", "info"),
    ("0.1", "low"),
    ("3.9", "low"),
    ("4", "med"),
    ("6.9", "med"),
    ("7", "high"),
    ("8.9", "high"),
    ("9", "critical"),
    ("10", "critical"),
]


def _vulners(cve, score=MISSING, exploit=False):
    return {"cve": cve, "score": score, "exploit": exploit}


def _port(protocol="tcp", port=443, vulners=None, scripts=None):
    return {
        "protocol": protocol,
        "port": port,
        "vulners": vulners or [],
        "scripts": scripts or [],
    }


def _nmap_xml(hosts):
    root = ET.Element("nmaprun")
    for ip, ports in hosts:
        host = ET.SubElement(root, "host")
        ET.SubElement(host, "status", {"state": "up"})
        ET.SubElement(host, "address", {"addr": ip, "addrtype": "ipv4"})
        ports_node = ET.SubElement(host, "ports")
        for port_spec in ports:
            port = ET.SubElement(
                ports_node,
                "port",
                {
                    "protocol": port_spec["protocol"],
                    "portid": str(port_spec["port"]),
                },
            )
            ET.SubElement(port, "state", {"state": "open"})
            ET.SubElement(
                port,
                "service",
                {"name": "https" if port_spec["protocol"] == "tcp" else "domain"},
            )
            if port_spec["vulners"]:
                script = ET.SubElement(
                    port,
                    "script",
                    {"id": "vulners", "output": "synthetic TEST-NET fixture"},
                )
                service_table = ET.SubElement(
                    script, "table", {"key": "cpe:/a:example:fixture:1.0"}
                )
                for entry in port_spec["vulners"]:
                    vulnerability_table = ET.SubElement(service_table, "table")
                    for key, value in (
                        ("is_exploit", "true" if entry["exploit"] else "false"),
                        ("cvss", entry["score"]),
                        ("id", entry["cve"]),
                        ("type", "cve"),
                    ):
                        if value is MISSING:
                            continue
                        elem = ET.SubElement(vulnerability_table, "elem", {"key": key})
                        elem.text = str(value)
            for script_spec in port_spec["scripts"]:
                ET.SubElement(
                    port,
                    "script",
                    {"id": script_spec["id"], "output": script_spec["output"]},
                )
    return ET.tostring(root, encoding="utf-8")


def _parse(xml, **options):
    plugin = NmapPlugin(**options)
    plugin.parseOutputString(xml)
    return plugin


def _entries(plugin):
    found = []
    for host in plugin.get_data()["hosts"]:
        for vuln in host["vulnerabilities"]:
            found.append({"host": host, "service": None, "vuln": vuln})
        for service in host["services"]:
            for vuln in service["vulnerabilities"]:
                found.append({"host": host, "service": service, "vuln": vuln})
    return found


@pytest.mark.parametrize(("score", "expected"), SCORE_CASES)
def test_cvss_scores_map_to_project_severity_bands(score, expected):
    plugin = _parse(
        _nmap_xml(
            [
                (
                    "192.0.2.10",
                    [_port(vulners=[_vulners("CVE-2024-1001", score)])],
                )
            ]
        )
    )

    entries = _entries(plugin)
    assert len(entries) == 1
    vuln = entries[0]["vuln"]
    assert vuln["severity"] == expected
    assert vuln["cvss2"] == {}
    assert vuln["cvss3"] == {}
    assert vuln["cvss4"] == {}

    summary = plugin.get_summary()
    assert summary["services_vulns"] == 1
    assert summary["severity_vulns"][expected] == 1


@pytest.mark.parametrize(
    "score",
    [MISSING, "", "not-a-number", "nan", "inf", "-1", "10.1"],
    ids=["missing", "empty", "malformed", "nan", "inf", "negative", "above-ten"],
)
def test_invalid_cvss_scores_are_unclassified(score):
    plugin = _parse(
        _nmap_xml(
            [
                (
                    "192.0.2.11",
                    [_port(vulners=[_vulners("CVE-2024-1002", score)])],
                )
            ]
        )
    )

    entries = _entries(plugin)
    assert len(entries) == 1
    vuln = entries[0]["vuln"]
    assert vuln["severity"] == "unclassified"
    assert vuln["cvss2"] == {}
    assert vuln["cvss3"] == {}
    assert vuln["cvss4"] == {}
    assert plugin.get_summary()["severity_vulns"]["unclassified"] == 1


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        (
            {"ignore_info": True},
            {"CVE-2024-1003": "critical", "CVE-2024-1004": "high"},
        ),
        (
            {"min_severity": "high"},
            {"CVE-2024-1003": "critical", "CVE-2024-1004": "high"},
        ),
        ({"max_severity": "high"}, {"CVE-2024-1004": "high"}),
    ],
    ids=["ignore-info", "min-high", "max-high"],
)
def test_filters_use_the_recovered_severity(options, expected):
    plugin = _parse(
        _nmap_xml(
            [
                (
                    "192.0.2.12",
                    [
                        _port(
                            vulners=[
                                _vulners("CVE-2024-1003", "9.8"),
                                _vulners("CVE-2024-1004", "7.5"),
                            ]
                        )
                    ],
                )
            ]
        ),
        **options,
    )

    found = {
        entry["vuln"]["name"]: entry["vuln"]["severity"] for entry in _entries(plugin)
    }
    assert found == expected
    assert plugin.get_summary()["services_vulns"] == len(expected)


def test_vulners_metadata_is_preserved_and_vectors_stay_empty():
    plugin = _parse(
        _nmap_xml(
            [
                (
                    "192.0.2.13",
                    [
                        _port(
                            vulners=[
                                _vulners("CVE-2024-1005", "9.8", exploit=True)
                            ]
                        )
                    ],
                )
            ]
        )
    )

    entries = _entries(plugin)
    assert len(entries) == 1
    vuln = entries[0]["vuln"]
    assert vuln["severity"] == "critical"
    assert vuln["name"] == "CVE-2024-1005"
    assert vuln["desc"] == "vulners-CVE-2024-1005 *EXPLOIT*"
    assert vuln["refs"] == [
        {"name": "https://vulners.com/cve/CVE-2024-1005", "type": "other"}
    ]
    assert vuln["cve"] == ["CVE-2024-1005"]
    assert vuln["cvss2"] == {}
    assert vuln["cvss3"] == {}
    assert vuln["cvss4"] == {}


def test_non_vulners_text_controls_are_unchanged():
    plugin = _parse(
        _nmap_xml(
            [
                (
                    "192.0.2.14",
                    [
                        _port(
                            scripts=[
                                {"id": "http-proof", "output": "State: VULNERABLE"},
                                {
                                    "id": "tls-proof",
                                    "output": "State: NOT VULNERABLE",
                                },
                            ]
                        )
                    ],
                )
            ]
        )
    )

    found = {
        entry["vuln"]["name"]: entry["vuln"]["severity"] for entry in _entries(plugin)
    }
    assert found == {"http-proof": "high", "tls-proof": "info"}
    assert plugin.get_summary()["services_vulns"] == 2


def test_duplicate_parse_adds_no_extra_findings():
    xml = _nmap_xml(
        [
            (
                "192.0.2.15",
                [_port(vulners=[_vulners("CVE-2024-1006", "7.5")])],
            )
        ]
    )
    plugin = _parse(xml)
    plugin.parseOutputString(xml)

    data = plugin.get_data()
    assert len(data["hosts"]) == 1
    assert len(data["hosts"][0]["services"]) == 1
    assert len(_entries(plugin)) == 1
    assert plugin.get_summary()["services_vulns"] == 1


def test_same_cve_on_different_host_service_and_protocol_is_retained():
    finding = [_vulners("CVE-2024-1007", "9.8")]
    plugin = _parse(
        _nmap_xml(
            [
                (
                    "192.0.2.16",
                    [
                        _port("tcp", 443, finding),
                        _port("tcp", 8443, finding),
                        _port("udp", 443, finding),
                    ],
                ),
                ("198.51.100.20", [_port("tcp", 443, finding)]),
            ]
        )
    )

    entries = _entries(plugin)
    assert len(entries) == 4
    locations = {
        (
            entry["host"]["ip"],
            entry["service"]["protocol"],
            entry["service"]["port"],
        )
        for entry in entries
    }
    assert locations == {
        ("192.0.2.16", "tcp", 443),
        ("192.0.2.16", "tcp", 8443),
        ("192.0.2.16", "udp", 443),
        ("198.51.100.20", "tcp", 443),
    }
    assert {entry["vuln"]["severity"] for entry in entries} == {"critical"}
    assert plugin.get_summary()["services_vulns"] == 4
