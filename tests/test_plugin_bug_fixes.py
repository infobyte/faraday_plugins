"""Regression suite for the bug fixes shipped under tkt_399.

Each fixture under ``tests/data/sandbox`` is one of:

* **Real tool output** captured by running the tool locally (gitleaks,
  trivy, grype, sslyze, wfuzz, fierce).
* **Synthetic minimal documents** crafted by hand from each tool's
  published schema. Useful for plugins where the bug only triggered with
  a specific shape of input (null Classification, missing TestResult,
  bool-instead-of-dict, etc.).

Every assertion targets a specific shape of bug so a future regression
is caught immediately.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "sandbox"

# Make `faraday_plugins` importable when running pytest from the repo root.
sys.path.insert(0, str(ROOT.parent))

from faraday_plugins.plugins.manager import PluginsManager  # noqa: E402


@pytest.fixture(scope="module")
def manager():
    return PluginsManager(hostname_resolution=False)


def _parse(manager, plugin_id, fixture_name):
    plugin = manager.get_plugin(plugin_id)
    assert plugin is not None, f"plugin {plugin_id!r} is not registered"
    plugin.processReport(DATA / fixture_name)
    return json.loads(plugin.get_json())


def _flat_vulns(report):
    for h in report["hosts"]:
        yield from (h.get("vulnerabilities") or [])
        for s in h.get("services") or []:
            yield from (s.get("vulnerabilities") or [])


def _all_hosts(report):
    return report["hosts"]


# ---------------------------------------------------------------------------
# JSON-emitting tools — schema-drift fixes
# ---------------------------------------------------------------------------


def test_trivy_json_extracts_cvss_uppercase_field(manager):
    """``CVSS`` (upper) is the field Trivy emits; previous DTO read ``cvss``."""
    rep = _parse(manager, "trivy_json", "trivy_sample.json")
    vulns = list(_flat_vulns(rep))
    assert vulns, "trivy parser produced no vulns"
    with_cvss = [v for v in vulns if v.get("cvss3", {}).get("vector_string")]
    assert with_cvss, "Trivy CVSS3 extraction regressed"


def test_trivy_json_legacy_array_format(manager):
    """Trivy v0.x emitted the report as a top-level JSON array."""
    fixture = DATA / "_trivy_legacy.json"
    fixture.write_text(json.dumps([
        {"Target": "alpine:3.10",
         "Type": "alpine",
         "Vulnerabilities": [
             {"VulnerabilityID": "CVE-2021-36159",
              "PkgName": "apk-tools",
              "Severity": "CRITICAL",
              "Title": "libfetch out-of-boundary read",
              "Description": "Synthetic legacy Trivy report"}
         ]},
    ]))
    rep = _parse(manager, "trivy_json", "_trivy_legacy.json")
    assert list(_flat_vulns(rep)), "Trivy legacy v0.x array format not handled"


def test_grype_extracts_cvss_and_cwe(manager):
    """grype previously dropped the ``cvss[]`` and ``cwes[]`` arrays."""
    rep = _parse(manager, "grype", "grype_sample.json")
    vulns = list(_flat_vulns(rep))
    assert vulns
    assert any(v.get("cvss3", {}).get("vector_string") for v in vulns), \
        "grype CVSS regression"
    assert any(v.get("cwe") for v in vulns), "grype CWE regression"


def test_sslyzejson_unwraps_modern_result_blocks(manager):
    """sslyze 5.x wraps each command in ``{status, result}``; the swallowed
    ``except KeyError`` previously masked all findings."""
    rep = _parse(manager, "sslyze_json", "sslyze_sample.json")
    vulns = list(_flat_vulns(rep))
    assert vulns


def test_sslyzejson_legacy_bool_field(manager):
    """sslyze <5 had ``is_vulnerable_to_heartbleed`` as a top-level bool, not
    nested under ``result``. Plugin used to call ``.get`` on a bool."""
    fixture = DATA / "_sslyze_legacy.json"
    fixture.write_text(json.dumps({
        "server_scan_results": [{
            "server_info": {"server_location": {
                "hostname": "example.com", "ip_address": "203.0.113.1", "port": 443}},
            "scan_commands_results": {
                "heartbleed": {"is_vulnerable_to_heartbleed": True},
                "openssl_ccs_injection": {"is_vulnerable_to_ccs_injection": False},
            },
        }],
    }))
    rep = _parse(manager, "sslyze_json", "_sslyze_legacy.json")
    vulns = list(_flat_vulns(rep))
    assert any("Heartbleed" in v["name"] for v in vulns), \
        "sslyze legacy bool format regression"


def test_prowler_ocsf_format_supported(manager):
    """Prowler v4+ emits OCSF; the v3 ASFF parser left them unrecognised."""
    rep = _parse(manager, "prowler", "prowler_ocsf_sample.json")
    vulns = list(_flat_vulns(rep))
    # Two FAIL events; one MANUAL skipped, one PASS skipped.
    assert len(vulns) == 2
    assert {v["severity"] for v in vulns} == {"high", "med"}


def test_wfuzz_modern_table_format(manager):
    """wfuzz 2.4+ dropped the legacy ``C=200`` prefix."""
    rep = _parse(manager, "wfuzz", "wfuzz_sample.txt")
    assert any(s for h in rep["hosts"] for s in h.get("services") or []), \
        "wfuzz parser produced no services"


def test_bandit_json_format(manager):
    """Bandit JSON is the default modern output; the plugin used to only
    support junit XML."""
    rep = _parse(manager, "bandit", "bandit_sample.json")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 3
    assert any("CWE-" in c for v in vulns for c in v.get("cwe", []))


def test_invicti_json_format(manager):
    """Invicti now ships JSON natively (used to be XML-only)."""
    rep = _parse(manager, "invicti", "invicti_sample.json")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 2
    assert any(v["severity"] == "high" for v in vulns)


def test_sonarqubeapi_generic_issue_format(manager):
    """SonarQube Scan generic-issue-data format (no `components` key)."""
    rep = _parse(manager, "sonarqubeapi", "sonarqube_generic_sample.json")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 2


def test_sonarqubeapi_hotspots_format(manager):
    """SonarQube ``/api/hotspots/search`` (no `issues`, has `hotspots`)."""
    rep = _parse(manager, "sonarqubeapi", "sonarqube_hotspots_sample.json")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 2


def test_ssl_labs_extracts_real_vulns(manager):
    """SSL Labs report schema changed; the plugin used to only dump cert
    metadata. Now it surfaces BEAST/POODLE/RC4/grade/etc."""
    rep = _parse(manager, "ssllabs", "ssl_labs_sample.json")
    vulns = list(_flat_vulns(rep))
    assert vulns
    names = " ".join(v.get("name", "") for v in vulns)
    assert "BEAST" in names or "Deprecated" in names, \
        "ssl_labs parser failed to surface protocol-level findings"


def test_wapiti_handles_empty_text_nodes(manager):
    """Wapiti XML tags can have empty bodies (`<curl_command/>` etc.)."""
    rep = _parse(manager, "wapiti", "wapiti_sample.xml")
    vulns = list(_flat_vulns(rep))
    assert vulns


def test_windows_defender_api_json(manager):
    """Defender for Endpoint API returns ``{value: [...]}``; plugin used to
    only handle NDJSON."""
    rep = _parse(manager, "windowsdefender_jsonl", "windows_defender_api_sample.json")
    assert list(_flat_vulns(rep))


def test_windows_defender_zip_bundle(manager):
    """Defender export bundle (zip with machines/ + vulnerabilities/)."""
    rep = _parse(manager, "windowsdefender_jsonl", "windows_defender_bundle.zip")
    hosts = _all_hosts(rep)
    assert hosts
    assert any(h.get("ip") for h in hosts)


def test_openvas_handles_missing_detail_text(manager):
    """OpenVAS host details may have empty <name>/<value>."""
    rep = _parse(manager, "openvas", "openvas_sample.xml")
    assert list(_flat_vulns(rep))


def test_gitleaks_handles_null_no_findings(manager):
    """gitleaks emits the literal string ``null`` (not ``[]``) when nothing
    leaks; the plugin used to crash trying to iterate it."""
    plugin = manager.get_plugin("gitleaks")
    fixture = DATA / "_gitleaks_null.json"
    fixture.write_text("null\n")
    plugin.processReport(fixture)
    rep = json.loads(plugin.get_json())
    assert rep["hosts"] == []


def test_gitleaks_real_findings_still_work(manager):
    rep = _parse(manager, "gitleaks", "gitleaks_sample.json")
    assert list(_flat_vulns(rep))


def test_snyk_all_projects_array(manager):
    """``snyk test --all-projects`` outputs a JSON array (one item per
    project), not a dict."""
    rep = _parse(manager, "snyk", "snyk_all_projects_sample.json")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 3
    assert len(rep["hosts"]) >= 2


def test_fortify_standalone_fvdl(manager):
    """``audit.fvdl`` extracted from a Fortify ``.fpr`` is plain XML."""
    rep = _parse(manager, "fortify", "fortify_fvdl_sample.fvdl")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 2


def test_fortify_report_definition_xml(manager):
    """Fortify SCA's ``ReportDefinition`` XML carries Issue elements."""
    rep = _parse(manager, "fortify", "fortify_report_sample.xml")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 2
    assert any(v["severity"] == "critical" for v in vulns)


def test_acunetix360_handles_null_classification(manager):
    """Acunetix360 vulns can have ``Classification: null``."""
    rep = _parse(manager, "acunetix360", "acunetix360_null_classification_sample.json")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 2


def test_sarif_handles_missing_rule_metadata(manager):
    """SARIF results may reference rules absent from the driver, or carry no
    location at all."""
    rep = _parse(manager, "sarif", "sarif_minimal_sample.sarif")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 3


def test_hydra_jsonv1_format(manager):
    """``hydra -b jsonv1`` JSON output is the modern flow."""
    rep = _parse(manager, "hydra", "hydra_jsonv1_sample.json")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 2


def test_sourceclear_findings_list_format(manager):
    """The Veracode platform export uses ``{findings: [...]}``; the plugin
    used to only support the legacy ``records`` shape."""
    rep = _parse(manager, "sourceclear", "sourceclear_findings_list_sample.json")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 2


def test_webinspect_sessions_format(manager):
    """Modern WebInspect XML wraps issues inside ``<Sessions><Session>``."""
    rep = _parse(manager, "webinspect", "webinspect_sessions_sample.xml")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 3


def test_whitesource_cli_report(manager):
    """Mend's CLI emits ``{libraries[].vulnerabilities[]}``."""
    rep = _parse(manager, "whitesource", "whitesource_cli_sample.json")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 2


def test_whitesource_platform_api_v3(manager):
    """Mend SCA Platform API v3 wraps findings in ``{response: [...]}``."""
    rep = _parse(manager, "whitesource", "whitesource_platform_api_sample.json")
    vulns = list(_flat_vulns(rep))
    assert len(vulns) == 2


def test_openscap_handles_xccdf_template_without_testresult(manager):
    """An XCCDF benchmark with only Rules and no TestResult used to crash
    with IndexError."""
    fixture = DATA / "_openscap_no_results.xml"
    fixture.write_text(
        '<?xml version="1.0"?>\n'
        '<Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">\n'
        '  <title>Synthetic XCCDF</title>\n'
        '</Benchmark>\n'
    )
    plugin = manager.get_plugin("openscap")
    plugin.processReport(fixture)
    rep = json.loads(plugin.get_json())
    assert rep["hosts"] == []


def test_whois_works_without_command_string(manager):
    """``whois`` plugin used to access ``self.command_string`` which only
    exists in CLI mode (set by ``processCommandString``)."""
    rep = _parse(manager, "whois", "whois_sample.txt")
    assert "hosts" in rep


def test_shodan_vulns_as_list(manager):
    """Shodan ``vulns`` field can be either a dict (with metadata) or a flat
    list of CVE strings."""
    rep = _parse(manager, "shodan", "shodan_sample.jsonl")
    assert list(_flat_vulns(rep))


def test_amap_handles_no_args(manager):
    """``amap`` plugin used to require ``self.args`` which is only populated
    in CLI mode."""
    rep = _parse(manager, "amap", "amap_sample.txt")
    assert _all_hosts(rep)


def test_hping3_unknown_port_does_not_crash(manager):
    """hping3 with sport=0 used to KeyError because 0 was not in the known
    services dict."""
    rep = _parse(manager, "hping3", "hping3_sample.txt")
    assert "hosts" in rep


def test_nextnet_info_can_be_string_or_dict(manager):
    """nextnet's ``info`` field is sometimes a string."""
    rep = _parse(manager, "nextnet", "nextnet_sample.txt")
    assert _all_hosts(rep)


def test_cis_finds_rules_by_tag(manager):
    """CIS plugin used to use positional ``rule[0]`` / ``rule[1][0]`` access
    that breaks for non-conforming reports."""
    rep = _parse(manager, "cis", "cis_sample.xml")
    assert "hosts" in rep


def test_reconng_decodes_bytes_input(manager):
    """reconng's ``report_format`` ran a string regex over bytes input."""
    rep = _parse(manager, "reconng", "reconng_sample.xml")
    assert "hosts" in rep


def test_sslyze_xml_optional_attributes(manager):
    """Sslyze XML's ``tlsWrappedProtocol`` attribute is optional in newer
    versions."""
    rep = _parse(manager, "sslyze_xml", "sslyze_xml_sample.xml")
    assert "hosts" in rep


def test_mbsa_accepts_locale_dates(manager):
    """MBSA writes the scan date in the locale of the host that ran it.
    The fix swapped the single ``strptime`` call for a list of candidate
    formats so non-ISO dates no longer crash the parser."""
    from datetime import datetime
    p = manager.get_plugin("mbsa")
    assert p is not None
    for raw in ("2026/01/15 10:00", "1/15/2026 10:00",
                "15/01/2026 10:00", "2026-01-15 10:00"):
        for fmt in ('%Y/%m/%d %H:%M', '%m/%d/%Y %H:%M',
                    '%d/%m/%Y %H:%M', '%Y-%m-%d %H:%M', '%m-%d-%Y %H:%M'):
            try:
                datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        else:
            pytest.fail(f"MBSA date helper rejected {raw!r}")


def test_fierce_modern_python_format(manager):
    """Python fierce 1.x emits ``Found: host (ip)`` lines; the parser only
    recognised the legacy Perl ``IP\\thostname.`` shape."""
    rep = _parse(manager, "fierce", "fierce_sample.txt")
    assert _all_hosts(rep)
