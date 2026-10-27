"""Auto-detection of tkt_399 reports (ReportAnalyzer, i.e. what `process-report` does without -p)."""
import json
from pathlib import Path

import pytest

from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer

DATA = Path(__file__).resolve().parent / "data" / "sandbox"

manager = PluginsManager(hostname_resolution=False)
analyzer = ReportAnalyzer(manager)


@pytest.mark.parametrize("fixture, plugin_id", [
    ("wfuzz_sample.txt", "Wfuzz"),
    ("whois_sample.txt", "whois"),
    ("amap_sample.txt", "Amap"),
    ("nextnet_sample.txt", "nextnet"),
    ("fierce_sample.txt", "Fierce"),
    ("hping3_sample.txt", "Hping3"),
    ("hydra_jsonv1_sample.json", "Hydra"),
    ("sonarqube_generic_sample.json", "sonarqubeAPI"),
    ("sonarqube_hotspots_sample.json", "sonarqubeAPI"),
    ("prowler_ocsf_sample.json", "prowler"),
    ("prowler_aws_v5_sample.csv", "prowler"),
    ("_trivy_legacy.json", "Trivy_Json"),
])
def test_report_is_autodetected(fixture, plugin_id):
    plugin = analyzer.get_plugin(str(DATA / fixture))
    assert plugin is not None, fixture
    assert plugin.id == plugin_id


def test_plain_text_is_not_claimed_by_any_plugin(tmp_path):
    report = tmp_path / "notes.txt"
    report.write_text("just some notes\nnothing to see here\n")
    assert analyzer.get_plugin(str(report)) is None


def test_prowler_csv_reports_failed_unmuted_findings_only():
    plugin = manager.get_plugin("prowler")
    plugin.processReport(DATA / "prowler_aws_v5_sample.csv")
    report = json.loads(plugin.get_json())
    vulns = [v for h in report["hosts"] for v in h["vulnerabilities"]]
    assert len(vulns) == 3  # one PASS and one muted FAIL are skipped
    assert {v["severity"] for v in vulns} == {"critical", "high"}
    assert all(v["external_id"].startswith("PROWLER-") for v in vulns)


@pytest.mark.parametrize("fixture, plugin_id", [
    ("openvas_sample.xml", "Openvas"),
    ("sourceclear_findings_list_sample.json", "sourceclear"),
])
def test_report_not_stolen_by_similar_plugin(fixture, plugin_id):
    assert analyzer.get_plugin(str(DATA / fixture)).id == plugin_id


def test_snyk_all_projects_detected_by_file_name(tmp_path):
    report = tmp_path / "scan_faraday_snyk.json"
    report.write_text((DATA / "snyk_all_projects_sample.json").read_text())
    assert analyzer.get_plugin(str(report)).id == "Snyk"
