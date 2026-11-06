"""
Faraday Penetration Test IDE
See the file 'doc/LICENSE' for the license information

Regression tests for the WPScan JSON importer URL -> host/service mapping.

The tests exercise the product's own JSON consumer (WPScanPlugin.parseOutputString,
which builds the Faraday host and WordPress service records) and the component
under change (WPScanJsonParser.parse_url) through a recording resolver.

WPScanPlugin(hostname_resolution=False) is the product's genuine no-DNS option
(faraday_plugins/plugins/plugin.py, Plugin.resolve_hostname), so no resolver stub
is needed and no socket call can be reached from the consumer path.

Disclosed stdlib behaviour: urllib.parse gives the hostname component with
userinfo removed, IPv6 brackets removed and the host lowercased. That is the
intentional correct-component selection, not a byte-identical echo of netloc.
"""
import json

import pytest

from faraday_plugins.plugins.repo.wpscan.plugin import WPScanJsonParser, WPScanPlugin

# Reserved documentation address: the recorder never resolves anything.
RECORDED_ADDRESS = "203.0.113.7"


class ResolverRecorder:
    """Records the hostname handed to the resolver and returns a fixed address."""

    def __init__(self):
        self.calls = []

    def __call__(self, hostname):
        self.calls.append(hostname)
        return RECORDED_ADDRESS


def wpscan_json(target_url):
    """A genuine shaped WPScan JSON report (target_url + effective_url + plugins)."""
    return {
        "target_url": target_url,
        "effective_url": target_url,
        "interesting_findings": [
            {
                "type": "headers",
                "to_s": "Server: nginx",
                "references": {},
            }
        ],
        "plugins": {
            "akismet": {
                "vulnerabilities": [
                    {
                        "title": "Akismet < 4.1.2 - Unauthenticated Stored XSS",
                        "references": {
                            "url": ["https://wpvulndb.com/vulnerabilities/6f0d4b1a"],
                            "cve": ["2015-9357"],
                            "wpvulndb": ["6f0d4b1a-4b1e-4d0f-9d6a-1f2b3c4d5e6f"],
                        },
                    }
                ]
            }
        },
    }


def import_report(target_url):
    """Run the real importer and return (host record, WordPress service record)."""
    plugin = WPScanPlugin(hostname_resolution=False)
    plugin.parseOutputString(json.dumps(wpscan_json(target_url)))
    data = plugin.get_data()
    assert len(data["hosts"]) == 1, data["hosts"]
    host = data["hosts"][0]
    assert len(host["services"]) == 1, host["services"]
    return host, host["services"][0]


def parse_url(url):
    recorder = ResolverRecorder()
    parser = WPScanJsonParser(json.dumps({"target_url": url}), recorder)
    return parser.parse_url(url), recorder


CASES = [
    # url, expected hostname, expected protocol, expected port
    ("https://wp.example.test:8443/", "wp.example.test", "https", 8443),
    ("http://wp.example.test:8080/", "wp.example.test", "http", 8080),
    ("https://wp.example.test/", "wp.example.test", "https", 443),
    ("http://wp.example.test/", "wp.example.test", "http", 80),
    ("http://wp.example.test", "wp.example.test", "http", 80),
    ("https://[2001:db8::1]:9443/", "2001:db8::1", "https", 9443),
    ("https://user:pass@wp.example.test:8443/admin", "wp.example.test", "https", 8443),
    ("https://WP.Example.Test/", "wp.example.test", "https", 443),
    ("https://wp.example.test:0/", "wp.example.test", "https", 0),
]


@pytest.mark.parametrize("url,hostname,protocol,port", CASES)
def test_importer_host_and_service_use_url_components(url, hostname, protocol, port):
    host, service = import_report(url)
    assert host["hostnames"] == [hostname]
    assert host["ip"] == hostname
    assert service["name"] == "WordPress"
    assert service["protocol"] == protocol
    assert service["port"] == port


@pytest.mark.parametrize("url,hostname,protocol,port", CASES)
def test_parser_returns_clean_components_and_receives_clean_hostname(
    url, hostname, protocol, port
):
    parsed, recorder = parse_url(url)
    assert parsed["hostname"] == hostname
    assert parsed["protocol"] == protocol
    assert parsed["port"] == port
    assert parsed["address"] == RECORDED_ADDRESS
    assert recorder.calls == [hostname]


def test_unaffected_scheme_defaults_and_unparsable_ports_are_unchanged():
    # Unsupported scheme keeps the parsed values (no entry in the defaults table).
    parsed, _ = parse_url("ftp://wp.example.test:2121/")
    assert parsed == {
        "protocol": "ftp",
        "hostname": "wp.example.test",
        "port": 2121,
        "address": RECORDED_ADDRESS,
    }
    # A non-numeric port stays a real urllib.parse error, not a silent default.
    with pytest.raises(ValueError):
        parse_url("http://wp.example.test:not-a-port/")


def test_importer_keeps_vulnerability_and_finding_payload():
    host, service = import_report("https://wp.example.test:8443/")
    vulns = {v["name"]: v for v in service["vulnerabilities"]}
    assert set(vulns) == {
        "akismet: Akismet < 4.1.2 - Unauthenticated Stored XSS",
        "Server: nginx",
    }
    plugin_vuln = vulns["akismet: Akismet < 4.1.2 - Unauthenticated Stored XSS"]
    assert plugin_vuln["severity"] == "unclassified"
    assert plugin_vuln["external_id"] == "6f0d4b1a-4b1e-4d0f-9d6a-1f2b3c4d5e6f"
    assert plugin_vuln["cve"] == ["CVE-2015-9357"]
    assert plugin_vuln["refs"] == [
        {"name": "https://wpvulndb.com/vulnerabilities/6f0d4b1a", "type": "other"}
    ]
