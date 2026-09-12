import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer
from faraday_plugins.plugins.repo.gowitness.plugin import GowitnessPlugin


REPORT_FILE = Path(__file__).parent / "data" / "gowitness" / "gowitness_3_1_1.jsonl"


def _get_host(ip, hosts):
    return next(host for host in hosts if host["ip"] == ip)


def _get_service(port, services):
    return next(service for service in services if service["port"] == port)


def _valid_result(url, **overrides):
    result = {
        "url": url,
        "probed_at": "2026-07-10T12:34:56Z",
        "final_url": url,
        "response_code": 200,
        "response_reason": "OK",
        "protocol": "h2",
        "content_length": 100,
        "title": "Test page",
        "perception_hash": "test-hash",
        "file_name": "test.png",
        "failed": False,
        "tls": {},
        "technologies": [],
    }
    result.update(overrides)
    return result


def _processed_report():
    plugin = ReportAnalyzer(PluginsManager()).get_plugin(REPORT_FILE)
    plugin.resolve_hostname = Mock(return_value="203.0.113.10")
    plugin.processReport(REPORT_FILE)
    return plugin, json.loads(plugin.get_json())


def test_report_analyzer_detects_jsonl_and_json(tmp_path):
    analyzer = ReportAnalyzer(PluginsManager())

    plugin = analyzer.get_plugin(REPORT_FILE)
    assert plugin is not None
    assert plugin.id == "gowitness"
    assert plugin.name == "Gowitness"
    assert plugin.version == "3.1.1"
    assert plugin.extension == [".json", ".jsonl"]

    json_report = tmp_path / "gowitness.json"
    json_report.write_text(REPORT_FILE.read_text())
    assert analyzer.get_plugin(json_report).id == "gowitness"


def test_process_report_maps_hosts_services_and_web_records():
    plugin, report = _processed_report()

    assert plugin.resolve_hostname.call_count == 4
    plugin.resolve_hostname.assert_any_call("redirected.example.test")
    assert len(report["hosts"]) == 1
    host = _get_host("203.0.113.10", report["hosts"])
    assert set(host["hostnames"]) == {
        "example.test",
        "redirected.example.test",
    }

    assert len(host["services"]) == 3
    services = {
        (service["name"], service["protocol"], service["port"])
        for service in host["services"]
    }
    assert services == {
        ("http", "tcp", 80),
        ("https", "tcp", 443),
        ("https", "tcp", 8443),
    }

    https_service = _get_service(443, host["services"])
    assert https_service["version"] == "h2"
    assert https_service["description"] == "Gowitness web service using h2"
    assert len(https_service["vulnerabilities"]) == 2
    assert {
        vulnerability["path"]
        for vulnerability in https_service["vulnerabilities"]
    } == {"/", "/admin"}

    redirected = next(
        vulnerability
        for vulnerability in https_service["vulnerabilities"]
        if vulnerability["path"] == "/admin"
    )
    assert redirected["type"] == "VulnerabilityWeb"
    assert redirected["severity"] == "info"
    assert redirected["status"] == "open"
    assert redirected["website"] == "https://redirected.example.test"
    assert redirected["query"] == "view=full"
    assert redirected["method"] == "GET"
    assert redirected["status_code"] == 200
    assert redirected["run_date"] == datetime(
        2026, 7, 10, 12, 35, 56, tzinfo=timezone.utc
    ).timestamp()
    assert "http://example.test/legacy" in redirected["desc"]
    assert "h2 200 OK" in redirected["response"]
    assert "Screenshot file: admin.png" in redirected["data"]
    assert "Technologies: Go" in redirected["data"]
    assert "TLS protocol: TLS 1.3" in redirected["data"]

    explicit_port = _get_service(8443, host["services"])["vulnerabilities"][0]
    assert explicit_port["website"] == "https://example.test:8443"


def test_skips_bad_records_without_losing_later_results():
    plugin = GowitnessPlugin()
    plugin.logger = Mock()
    plugin.resolve_hostname = Mock(return_value="203.0.113.20")
    records = [
        json.dumps(_valid_result("https://example.test/before")),
        "",
        "{malformed json",
        json.dumps(_valid_result("https://example.test/failed", failed=True)),
        json.dumps(_valid_result("ftp://example.test/not-http")),
        json.dumps(_valid_result("https://example.test:invalid/bad-port")),
        json.dumps(["not", "an", "object"]),
        json.dumps(_valid_result("https://example.test/after")),
    ]

    plugin.parseOutputString("\n".join(records))
    report = json.loads(plugin.get_json())
    vulnerabilities = [
        vulnerability
        for host in report["hosts"]
        for service in host["services"]
        for vulnerability in service["vulnerabilities"]
    ]

    assert {vulnerability["path"] for vulnerability in vulnerabilities} == {
        "/before",
        "/after",
    }
    assert plugin.logger.warning.call_count == 2


def test_does_not_copy_embedded_or_sensitive_payloads():
    _, report = _processed_report()
    serialized = json.dumps(report)

    excluded_markers = {
        "GOWITNESS_HTML_PAYLOAD_MARKER",
        "GOWITNESS_SCREENSHOT_PAYLOAD_MARKER",
        "GOWITNESS_HEADER_MARKER",
        "GOWITNESS_NETWORK_MARKER",
        "GOWITNESS_CONSOLE_MARKER",
        "GOWITNESS_COOKIE_MARKER",
    }
    assert not any(marker in serialized for marker in excluded_markers)
    assert "Screenshot file: home.png" in serialized


def test_falls_back_from_blank_final_url_and_redacts_url_credentials():
    plugin = GowitnessPlugin(hostname_resolution=False)
    result = _valid_result(
        "https://user:secret@example.test/private",
        final_url="   ",
    )

    plugin.parseOutputString(json.dumps(result))
    serialized = plugin.get_json()

    assert "user:secret" not in serialized
    assert "secret" not in serialized
    assert "https://example.test/private" in serialized


def test_plugin_options_are_forwarded_to_plugin_base():
    plugin = GowitnessPlugin(
        ignore_info=True,
        hostname_resolution=False,
        vuln_tag="gowitness",
        service_tag="web",
        host_tag="recon",
    )

    assert plugin.ignore_info is True
    assert plugin.hostname_resolution is False
    assert plugin.vuln_tag == "gowitness"
    assert plugin.service_tag == "web"
    assert plugin.host_tag == "recon"
