"""
Asset identity tests for the Tenable IO JSON export plugin.

These tests exercise the real plugin end to end: no mocking of host, service or
finding creation and no mocking of the host / finding caches, because the bug
under test only shows up through the real ``PluginBase`` caches (they hash the
host ``ip`` only).  Expected identity: each asset is addressed by its first
valid IPv4 literal, falling back to its first valid IPv6 literal; records with
no usable address are skipped instead of collapsing into one empty-host
identity.
"""

import json

import pytest

from faraday_plugins.plugins.repo.tenableio_export_json.plugin import TenableIOJSONExport

IPV6_ALPHA = "2001:db8::a"
IPV6_BETA = "2001:db8::b"
IPV6_GAMMA = "2001:db8::c"

SHARED_DEFINITION = {
    "id": 9001,
    "name": "Shared Host Finding",
    "description": "Identical host level finding present on several assets",
}
SSH_DEFINITION = {
    "id": 9002,
    "name": "SSH Weak Configuration",
    "description": "Finding attached to a regular service",
}
WEB_DEFINITION = {
    "id": 9003,
    "name": "Web Server Misconfiguration",
    "description": "Finding attached to a web service",
}


def make_record(vuln_id, asset, definition=None, **extra):
    record = {
        "id": vuln_id,
        "asset": asset,
        "definition": dict(definition if definition is not None else SHARED_DEFINITION),
    }
    record.update(extra)
    return record


def parse(records, **plugin_kwargs):
    plugin = TenableIOJSONExport(**plugin_kwargs)
    plugin.parseOutputString(json.dumps(records))
    return plugin


def hosts_of(plugin):
    return plugin.get_data()["hosts"]


def host_by_ip(hosts, ip):
    matches = [host for host in hosts if host["ip"] == ip]
    assert len(matches) == 1, (
        f"expected exactly one host addressed by {ip!r}, "
        f"got {sorted(host['ip'] for host in hosts)!r}"
    )
    return matches[0]


def all_host_vulns(hosts):
    return [vuln for host in hosts for vuln in host["vulnerabilities"]]


def all_service_vulns(hosts):
    return [
        vuln
        for host in hosts
        for service in host["services"]
        for vuln in service["vulnerabilities"]
    ]


@pytest.mark.parametrize(
    "ipv4_container",
    [
        pytest.param({"ipv4_addresses": []}, id="ipv4-empty-list"),
        pytest.param({}, id="ipv4-field-absent"),
    ],
)
def test_ipv6_only_assets_with_same_finding_stay_separate(ipv4_container):
    """Two IPv6-only assets must not collapse into one empty host.

    Before the fix both assets were created with an empty host name, so the
    host cache merged them and the identical finding was stored only once.
    """
    records = [
        make_record(
            "vuln-alpha",
            dict(ipv4_container, ipv6_addresses=[IPV6_ALPHA], host_name="node-alpha"),
        ),
        make_record(
            "vuln-beta",
            dict(ipv4_container, ipv6_addresses=[IPV6_BETA], host_name="node-beta"),
        ),
    ]

    hosts = hosts_of(parse(records))

    assert len(hosts) == 2
    assert [host["ip"] for host in hosts] == [IPV6_ALPHA, IPV6_BETA]
    assert host_by_ip(hosts, IPV6_ALPHA)["hostnames"] == ["node-alpha"]
    assert host_by_ip(hosts, IPV6_BETA)["hostnames"] == ["node-beta"]
    assert [len(host["vulnerabilities"]) for host in hosts] == [1, 1]
    assert len(all_host_vulns(hosts)) == 2
    assert all(host["ip"] for host in hosts)


def test_ipv6_services_keep_host_association_and_web_fallback():
    """Service records stay on their own IPv6 asset and the web fallback uses
    the canonical IPv6 literal when no fqdn / hostname is available."""
    records = [
        make_record(
            "vuln-ssh-alpha",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_ALPHA], "host_name": "node-alpha"},
            SSH_DEFINITION,
            port=22,
        ),
        make_record(
            "vuln-web-gamma",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_GAMMA]},
            WEB_DEFINITION,
            port=443,
        ),
        make_record(
            "vuln-web-beta",
            {
                "ipv4_addresses": [],
                "ipv6_addresses": [IPV6_BETA],
                "display_fqdn": "beta.example.com",
                "host_name": "node-beta",
            },
            WEB_DEFINITION,
            port=443,
        ),
    ]

    hosts = hosts_of(parse(records))

    assert len(hosts) == 3
    assert [host["ip"] for host in hosts] == [IPV6_ALPHA, IPV6_GAMMA, IPV6_BETA]

    alpha = host_by_ip(hosts, IPV6_ALPHA)
    assert [service["port"] for service in alpha["services"]] == [22]
    assert alpha["services"][0]["name"] == "ssh"
    assert alpha["services"][0]["vulnerabilities"][0]["type"] == "Vulnerability"
    assert "website" not in alpha["services"][0]["vulnerabilities"][0]

    gamma = host_by_ip(hosts, IPV6_GAMMA)
    assert [service["port"] for service in gamma["services"]] == [443]
    assert gamma["services"][0]["name"] == "https"
    gamma_vuln = gamma["services"][0]["vulnerabilities"][0]
    assert gamma_vuln["type"] == "VulnerabilityWeb"
    assert gamma_vuln["website"] == IPV6_GAMMA

    beta = host_by_ip(hosts, IPV6_BETA)
    assert [service["port"] for service in beta["services"]] == [443]
    assert beta["services"][0]["vulnerabilities"][0]["website"] == "beta.example.com"
    assert set(beta["hostnames"]) == {"beta.example.com", "node-beta"}


def test_hostname_priorities_preserved_for_ipv6_assets():
    """fqdn > host_name priority for the website field is unchanged for IPv6."""
    records = [
        make_record(
            "vuln-web-hostname",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_ALPHA], "host_name": "node-alpha"},
            WEB_DEFINITION,
            port=80,
        ),
        make_record(
            "vuln-web-fqdn",
            {
                "ipv4_addresses": [],
                "ipv6_addresses": [IPV6_BETA],
                "display_fqdn": "beta.example.com",
                "host_name": "node-beta",
            },
            WEB_DEFINITION,
            port=80,
        ),
    ]

    hosts = hosts_of(parse(records))

    assert host_by_ip(hosts, IPV6_ALPHA)["services"][0]["vulnerabilities"][0]["website"] == "node-alpha"
    assert host_by_ip(hosts, IPV6_BETA)["services"][0]["vulnerabilities"][0]["website"] == "beta.example.com"


def test_website_inherits_previously_cached_hostname_for_same_ipv6():
    """A later web record for the same canonical IPv6 inherits the hostname
    cached by an earlier record, even when it arrives in an equivalent expanded
    spelling and carries no host_name / display_fqdn."""
    expanded = "2001:0db8:0000:0000:0000:0000:0000:000a"
    records = [
        make_record(
            "vuln-hostname-first",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_ALPHA], "host_name": "node-alpha"},
        ),
        make_record(
            "vuln-web-expanded",
            {"ipv4_addresses": [], "ipv6_addresses": [expanded]},
            WEB_DEFINITION,
            port=443,
        ),
    ]

    hosts = hosts_of(parse(records))

    assert len(hosts) == 1
    host = hosts[0]
    assert host["ip"] == IPV6_ALPHA
    assert host["hostnames"] == ["node-alpha"]
    assert len(host["vulnerabilities"]) == 1
    assert [service["port"] for service in host["services"]] == [443]
    assert host["services"][0]["vulnerabilities"][0]["website"] == "node-alpha"


def test_duplicate_asset_and_finding_still_dedup():
    """Repeating the same asset + finding keeps a single host and a single
    finding, and distinct findings on one IPv6 asset are both kept."""
    asset = {"ipv4_addresses": [], "ipv6_addresses": [IPV6_ALPHA], "host_name": "node-alpha"}
    records = [
        make_record("vuln-dup-1", asset),
        make_record("vuln-dup-2", asset),
        make_record("vuln-other", asset, SSH_DEFINITION),
    ]

    hosts = hosts_of(parse(records))

    assert len(hosts) == 1
    host = host_by_ip(hosts, IPV6_ALPHA)
    assert len(host["vulnerabilities"]) == 2
    assert {vuln["name"] for vuln in host["vulnerabilities"]} == {
        SHARED_DEFINITION["name"],
        SSH_DEFINITION["name"],
    }


@pytest.mark.parametrize(
    "ipv6_literal",
    [
        pytest.param("2001:0db8:0000:0000:0000:0000:0000:0005", id="expanded"),
        pytest.param("2001:DB8::5", id="uppercase-compressed"),
        pytest.param("2001:db8::5", id="compressed"),
    ],
)
def test_ipv6_literal_forms_share_one_canonical_identity(ipv6_literal):
    """Equivalent spellings of one address inside the SAME parse are one asset.

    Each parametrization feeds the selected spelling and the compressed form in
    a single parse, both carrying the same host level finding. One host and one
    finding therefore prove the canonical literal (not string equality) drives
    host / finding cache identity.
    """
    records = [
        make_record("vuln-form-selected", {"ipv4_addresses": [], "ipv6_addresses": [ipv6_literal]}),
        make_record("vuln-form-compressed", {"ipv4_addresses": [], "ipv6_addresses": ["2001:db8::5"]}),
    ]

    hosts = hosts_of(parse(records))

    assert len(hosts) == 1
    assert hosts[0]["ip"] == "2001:db8::5"
    assert len(hosts[0]["vulnerabilities"]) == 1


@pytest.mark.parametrize(
    "asset,expected_ip",
    [
        pytest.param({"ipv4_addresses": ["10.0.0.7"]}, "10.0.0.7", id="ipv4-only"),
        pytest.param(
            {"ipv4_addresses": ["10.0.0.7"], "ipv6_addresses": [IPV6_ALPHA]},
            "10.0.0.7",
            id="dual-stack-prefers-ipv4",
        ),
        pytest.param(
            {"ipv4_addresses": [None, "", "not-an-ip", "  10.0.0.9  ", "10.0.0.10"]},
            "10.0.0.9",
            id="later-usable-ipv4-entry",
        ),
        pytest.param(
            {"ipv4_addresses": [], "ipv6_addresses": [None, 123, "  ", "bad-ip", IPV6_BETA]},
            IPV6_BETA,
            id="later-usable-ipv6-entry",
        ),
        pytest.param(
            {"ipv4_addresses": None, "ipv6_addresses": [IPV6_ALPHA]},
            IPV6_ALPHA,
            id="nonlist-ipv4-none-then-ipv6",
        ),
        pytest.param(
            {"ipv4_addresses": "not_a_list", "ipv6_addresses": [IPV6_BETA]},
            IPV6_BETA,
            id="nonlist-ipv4-string-then-ipv6",
        ),
        pytest.param(
            {"ipv4_addresses": {"0": "10.0.0.1"}, "ipv6_addresses": [IPV6_GAMMA]},
            IPV6_GAMMA,
            id="nonlist-ipv4-dict-then-ipv6",
        ),
        pytest.param(
            {"ipv4_addresses": ["2001:db8::1", "10.0.0.11"]},
            "10.0.0.11",
            id="wrongfamily-then-valid-ipv4-entry",
        ),
        pytest.param(
            {"ipv4_addresses": [], "ipv6_addresses": ["10.0.0.1", IPV6_BETA]},
            IPV6_BETA,
            id="wrongfamily-then-valid-ipv6-entry",
        ),
    ],
)
def test_first_valid_address_selection(asset, expected_ip):
    """IPv4 is preferred when valid, otherwise the first usable IPv6 literal is used."""
    hosts = hosts_of(parse([make_record("vuln-select", asset)]))

    assert [host["ip"] for host in hosts] == [expected_ip]


@pytest.mark.parametrize(
    "asset",
    [
        pytest.param({"ipv4_addresses": []}, id="ipv4-empty-list"),
        pytest.param({"ipv4_addresses": None}, id="ipv4-none"),
        pytest.param({"ipv4_addresses": "not_a_list"}, id="ipv4-string-container"),
        pytest.param({"ipv4_addresses": {"0": "10.0.0.1"}}, id="ipv4-dict-container"),
        pytest.param({"host_name": "no-address.example.com"}, id="no-address-fields"),
        pytest.param({"ipv4_addresses": [None, 123, "", "  ", "not-an-ip"]}, id="only-unusable-ipv4"),
        pytest.param({"ipv4_addresses": ["2001:db8::1"]}, id="ipv6-literal-in-ipv4-field"),
        pytest.param({"ipv4_addresses": [], "ipv6_addresses": ["10.0.0.1"]}, id="ipv4-literal-in-ipv6-field"),
        pytest.param({"ipv4_addresses": [], "ipv6_addresses": "2001:db8::1"}, id="ipv6-string-container"),
        pytest.param(
            {"ipv4_addresses": [], "ipv6_addresses": [None, {"x": 1}, ["2001:db8::1"]]},
            id="ipv6-unusable-entries",
        ),
        pytest.param({"ipv4_addresses": [], "ipv6_addresses": []}, id="both-empty-lists"),
    ],
)
def test_unaddressable_records_are_skipped_without_host(asset, caplog):
    """A record without any usable address creates no host, no service and no
    finding, logs once, and is not replaced by an empty-host identity."""
    plugin = TenableIOJSONExport()

    with caplog.at_level("ERROR"):
        plugin.parseOutputString(json.dumps([make_record("vuln-no-address", asset, SSH_DEFINITION, port=22)]))

    hosts = hosts_of(plugin)
    assert hosts == []
    assert all_host_vulns(hosts) == []
    assert all_service_vulns(hosts) == []
    assert caplog.messages == [
        "Omitting vulnerability vuln-no-address: asset has no usable IPv4 or IPv6 address"
    ]


def test_invalid_record_does_not_stop_following_records(caplog):
    """An unaddressable record is skipped and parsing continues with the next one."""
    records = [
        make_record("vuln-broken", {"ipv4_addresses": "not_a_list"}, SHARED_DEFINITION),
        make_record(
            "vuln-good",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_ALPHA], "host_name": "node-alpha"},
        ),
    ]

    with caplog.at_level("ERROR"):
        hosts = hosts_of(parse(records))

    assert [host["ip"] for host in hosts] == [IPV6_ALPHA]
    assert len(hosts[0]["vulnerabilities"]) == 1
    assert caplog.messages == [
        "Omitting vulnerability vuln-broken: asset has no usable IPv4 or IPv6 address"
    ]


def test_mixed_report_has_no_empty_host():
    """IPv4, IPv6 and unaddressable records in one report: every resulting host
    is addressed and the unaddressable record leaves no trace."""
    records = [
        make_record("vuln-ipv4", {"ipv4_addresses": ["10.0.0.1"], "host_name": "node-v4"}),
        make_record("vuln-ipv6", {"ipv4_addresses": [], "ipv6_addresses": [IPV6_ALPHA], "host_name": "node-v6"}),
        make_record("vuln-broken", {"ipv4_addresses": [], "ipv6_addresses": ["nope"]}),
        make_record("vuln-absent", {"host_name": "node-none"}),
    ]

    hosts = hosts_of(parse(records))

    assert [host["ip"] for host in hosts] == ["10.0.0.1", IPV6_ALPHA]
    assert "" not in [host["ip"] for host in hosts]
    assert [len(host["hostnames"]) for host in hosts] == [1, 1]


def test_min_severity_filters_with_real_cache_and_host_association():
    """min_severity keeps filtering findings while both IPv6 assets and their
    service associations survive."""
    records = [
        make_record(
            "vuln-low-alpha",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_ALPHA], "host_name": "node-alpha"},
            SSH_DEFINITION,
            port=22,
            severity=1,
        ),
        make_record(
            "vuln-high-alpha",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_ALPHA], "host_name": "node-alpha"},
            SHARED_DEFINITION,
            port=22,
            severity=3,
        ),
        make_record(
            "vuln-low-beta",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_BETA], "host_name": "node-beta"},
            SSH_DEFINITION,
            port=22,
            severity=1,
        ),
        make_record(
            "vuln-high-beta-ssh",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_BETA], "host_name": "node-beta"},
            SHARED_DEFINITION,
            port=22,
            severity=3,
        ),
        make_record(
            "vuln-high-beta",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_BETA], "host_name": "node-beta"},
            WEB_DEFINITION,
            port=443,
            severity=3,
        ),
    ]

    hosts = hosts_of(parse(records, min_severity="high"))

    assert len(hosts) == 2
    assert [host["ip"] for host in hosts] == [IPV6_ALPHA, IPV6_BETA]

    alpha = host_by_ip(hosts, IPV6_ALPHA)
    assert [service["port"] for service in alpha["services"]] == [22]
    assert [vuln["name"] for vuln in alpha["services"][0]["vulnerabilities"]] == [
        SHARED_DEFINITION["name"]
    ]

    beta = host_by_ip(hosts, IPV6_BETA)
    assert [service["port"] for service in beta["services"]] == [22, 443]
    kept = {(service["port"], vuln["name"]) for service in beta["services"] for vuln in service["vulnerabilities"]}
    assert kept == {(22, SHARED_DEFINITION["name"]), (443, WEB_DEFINITION["name"])}
    assert all(vuln["severity"] == "high" for vuln in all_service_vulns(hosts))


def test_process_report_with_ipv6_only_assets(tmp_path):
    """The report file path keeps the same identity behaviour (real plugin,
    real caches, no mocks)."""
    report = [
        make_record(
            "vuln-file-alpha",
            {"ipv4_addresses": [], "ipv6_addresses": [IPV6_ALPHA], "host_name": "node-alpha"},
        ),
        make_record(
            "vuln-file-beta",
            {"ipv6_addresses": [IPV6_BETA], "host_name": "node-beta"},
        ),
    ]
    report_path = tmp_path / "tenableio_ipv6_only.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    plugin = TenableIOJSONExport()
    plugin.processReport(report_path)
    data = plugin.get_data()

    assert data["command"]["import_source"] == "report"
    assert len(data["hosts"]) == 2
    assert [host["ip"] for host in data["hosts"]] == [IPV6_ALPHA, IPV6_BETA]
    assert len(all_host_vulns(data["hosts"])) == 2
