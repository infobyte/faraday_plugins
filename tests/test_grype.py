"""
Tests for the Grype JSON importer.

The scenarios mirror the shape of real Grype reports: one advisory routinely
matches several installed packages of the same image (for example Grype 0.66.0
reports CVE-2020-12413 against nspr, nss, nss-softokn, nss-softokn-freebl,
nss-sysinit and nss-util). Those matches share the host vulnerability identity
(name + description), so the importer must keep every component's evidence in a
single row instead of silently keeping only the first artifact.

All reports are built here; no external report, network access or fixture
directory outside this file is required.
"""
import json

import pytest

from faraday_plugins.plugins.repo.grype.plugin import GrypePlugin

CVE = "CVE-2020-12413"
DESC = (
    "The Raccoon attack is a timing attack on DHE ciphersuites inherit in the TLS "
    "specification. To mitigate this vulnerability, Firefox disabled support for "
    "DHE ciphersuites."
)


def _related(data_source="https://nvd.nist.gov/vuln/detail/CVE-2020-12413",
             description=DESC, severity="High", links=None, urls=None):
    return {
        "id": CVE,
        "dataSource": data_source,
        "namespace": "nvd:cpe",
        "severity": severity,
        "urls": urls if urls is not None else [data_source],
        "description": description,
        **({"links": links} if links is not None else {}),
    }


def match(artifact="nspr", version="4.34.0-17.el9_1", artifact_type="rpm",
          vuln_id=CVE, description=DESC, severity="High", metadata=None,
          related=True, related_links=None, related_urls=None,
          data_source="https://nvd.nist.gov/vuln/detail/CVE-2020-12413",
          vuln_urls=None):
    """One Grype match. `related=False` exercises the direct vulnerability path."""
    entry = {
        "vulnerability": {
            "id": vuln_id,
            "dataSource": data_source,
            "namespace": "nvd:cpe",
            "severity": severity,
            "urls": vuln_urls if vuln_urls is not None else [data_source],
            "description": description,
            "fix": {"versions": ["3.79.1"], "state": "fixed"},
            "advisories": [],
        },
        "artifact": {
            "id": f"pkg-{artifact}-{version}",
            "name": artifact,
            "version": version,
            "type": artifact_type,
            "locations": [{"path": f"/usr/lib64/lib{artifact}.so"}],
            "language": "",
            "licenses": [],
            "cpes": [],
            "purl": f"pkg:rpm/redhat/{artifact}@{version}",
            "metadata": metadata,
        },
    }
    if related:
        entry["relatedVulnerabilities"] = [
            _related(data_source=data_source, description=description,
                     severity=severity, links=related_links, urls=related_urls)
        ]
    return entry


def report(matches, user_input="registry.example.com/keycloak:21.1", tags=None,
           target_as_string=False, source_type="image"):
    target = (user_input if target_as_string
              else {"userInput": user_input, "imageID": "sha256:" + "0" * 64,
                    "tags": tags or [], "architecture": "amd64", "os": "linux"})
    payload = {
        "source": {"type": source_type, "target": target},
        "distro": {"name": "rhel", "version": "9.1", "idLike": ["rhel", "fedora"]},
        "descriptor": {"name": "grype", "version": "0.66.0",
                       "configuration": {"output": ["json"]},
                       "db": {"built": "2023-02-01T00:00:00Z", "schemaVersion": "5"}},
        "matches": matches,
    }
    if tags is not None:
        payload["image"] = {"tags": tags}
    return payload


def run_plugin(tmp_path, payload, **plugin_kwargs):
    """Runs the real importer over a real file and returns (plugin, report json)."""
    path = tmp_path / "grype.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    plugin = GrypePlugin(hostname_resolution=False, **plugin_kwargs)
    plugin.processReport(path)
    return plugin, json.loads(plugin.get_json())


def vulns(report_json):
    assert len(report_json["hosts"]) == 1
    return report_json["hosts"][0]["vulnerabilities"]


def data_lines(vuln):
    return vuln["data"].split("\n")


# --------------------------------------------------------------------------- #
# Core evidence preservation
# --------------------------------------------------------------------------- #

def test_distinct_packages_same_advisory_keep_every_component(tmp_path):
    _, out = run_plugin(tmp_path, report([
        match("nspr", "4.34.0-17.el9_1"),
        match("nss", "3.79.0-17.el9_1"),
        match("nss-util", "3.79.0-17.el9_1"),
    ]))

    rows = vulns(out)
    assert len(rows) == 1
    row = rows[0]
    assert row["name"] == CVE
    assert row["cve"] == [CVE]
    # Exact strings keep the importer's existing formatting (no space before
    # "Version:"), so a single-match render stays byte-identical.
    assert data_lines(row) == [
        "Artifact: nsprVersion: 4.34.0-17.el9_1 Type: rpm",
        "Artifact: nssVersion: 3.79.0-17.el9_1 Type: rpm",
        "Artifact: nss-utilVersion: 3.79.0-17.el9_1 Type: rpm",
    ]


def test_same_package_two_versions_are_both_retained(tmp_path):
    _, out = run_plugin(tmp_path, report([
        match("nspr", "4.34.0-17.el9_1"),
        match("nspr", "4.33.0-1.el9"),
    ]))

    rows = vulns(out)
    assert len(rows) == 1
    assert data_lines(rows[0]) == [
        "Artifact: nsprVersion: 4.34.0-17.el9_1 Type: rpm",
        "Artifact: nsprVersion: 4.33.0-1.el9 Type: rpm",
    ]


def test_exact_duplicate_match_is_not_repeated_in_data(tmp_path):
    single = match("nspr", "4.34.0-17.el9_1")
    _, out = run_plugin(tmp_path, report([single, json.loads(json.dumps(single))]))

    rows = vulns(out)
    assert len(rows) == 1
    assert data_lines(rows[0]) == ["Artifact: nsprVersion: 4.34.0-17.el9_1 Type: rpm"]


def test_different_advisories_stay_separate(tmp_path):
    _, out = run_plugin(tmp_path, report([
        match("nss", "3.79.0-17.el9_1"),
        match("nss", "3.79.0-17.el9_1", vuln_id="CVE-2022-34479",
              description="A different advisory description.",
              data_source="https://nvd.nist.gov/vuln/detail/CVE-2022-34479"),
    ]))

    rows = vulns(out)
    assert [row["name"] for row in rows] == [CVE, "CVE-2022-34479"]


def test_same_advisory_with_different_description_stays_separate(tmp_path):
    """Grouping is description-sensitive, matching the existing cache identity."""
    _, out = run_plugin(tmp_path, report([
        match("nss", "3.79.0-17.el9_1"),
        match("nspr", "4.34.0-17.el9_1",
              description="A different provider description for the same advisory.",
              data_source="https://access.redhat.com/errata/RHSA-2022:0001"),
    ]))

    rows = vulns(out)
    assert len(rows) == 2
    assert all(len(data_lines(row)) == 1 for row in rows)


# --------------------------------------------------------------------------- #
# Severity and reference aggregation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("reverse", [False, True])
def test_refs_are_unioned_and_highest_severity_wins_in_any_order(tmp_path, reverse):
    def refs_of(entry):
        related = entry["relatedVulnerabilities"][0]
        return [related["dataSource"], *related["urls"]]

    low = match("nspr", "4.34.0-17.el9_1", severity="Low",
                data_source="https://nvd.nist.gov/vuln/detail/CVE-2020-12413",
                related_urls=["https://nvd.nist.gov/vuln/detail/CVE-2020-12413",
                              "https://access.redhat.com/errata/RHSA-2022:0001"])
    critical = match("nss", "3.79.0-17.el9_1", severity="Critical",
                     data_source="https://github.com/advisories/GHSA-test",
                     related_urls=["https://github.com/advisories/GHSA-test",
                                   "https://github.com/advisories/GHSA-test?ref=cve"])
    matches = [critical, low] if reverse else [low, critical]

    _, out = run_plugin(tmp_path, report(matches))

    rows = vulns(out)
    assert len(rows) == 1
    row = rows[0]
    assert row["severity"] == "critical"
    first, second = (critical, low) if reverse else (low, critical)
    # The first match's references are kept verbatim; later matches only add the
    # ones not already present, in first-seen order.
    expected_refs = list(refs_of(first))
    for reference in refs_of(second):
        if reference not in expected_refs:
            expected_refs.append(reference)
    assert [ref["name"] for ref in row["refs"]] == expected_refs
    assert data_lines(row) == [
        f"Artifact: {first['artifact']['name']}Version: "
        f"{first['artifact']['version']} Type: {first['artifact']['type']}",
        f"Artifact: {second['artifact']['name']}Version: "
        f"{second['artifact']['version']} Type: {second['artifact']['type']}",
    ]


def test_second_match_adds_only_unseen_references(tmp_path):
    """The first match keeps its references verbatim (including its own repeated
    dataSource/urls pair, as before this change); later matches only add new ones."""
    nvd = "https://nvd.nist.gov/vuln/detail/CVE-2020-12413"
    _, out = run_plugin(tmp_path, report([
        match("nspr", "4.34.0-17.el9_1", related_urls=[nvd]),
        match("nss", "3.79.0-17.el9_1",
              related_urls=[nvd, "https://access.redhat.com/errata/RHSA-2022:0001"]),
    ]))

    row = vulns(out)[0]
    assert [ref["name"] for ref in row["refs"]] == [
        nvd,
        nvd,
        "https://access.redhat.com/errata/RHSA-2022:0001",
    ]


# --------------------------------------------------------------------------- #
# Per-match severity filtering happens before aggregation
# --------------------------------------------------------------------------- #

def test_ignore_info_excludes_only_the_info_artifact(tmp_path):
    info = match("nspr", "4.34.0-17.el9_1", severity="Negligible",
                 data_source="https://nvd.nist.gov/vuln/detail/CVE-2020-12413")
    high = match("nss", "3.79.0-17.el9_1", severity="High",
                 data_source="https://github.com/advisories/GHSA-test")

    _, out = run_plugin(tmp_path, report([info, high]), ignore_info=True)

    rows = vulns(out)
    assert len(rows) == 1
    assert data_lines(rows[0]) == ["Artifact: nssVersion: 3.79.0-17.el9_1 Type: rpm"]
    assert rows[0]["severity"] == "high"
    assert any("GHSA-test" in ref["name"] for ref in rows[0]["refs"])
    assert not any("nvd.nist.gov" in ref["name"] for ref in rows[0]["refs"])


def test_min_severity_excludes_low_member_before_aggregation(tmp_path):
    low = match("nspr", "4.34.0-17.el9_1", severity="Low")
    high = match("nss", "3.79.0-17.el9_1", severity="High",
                 data_source="https://github.com/advisories/GHSA-test")

    _, out = run_plugin(tmp_path, report([low, high]), min_severity="high")

    rows = vulns(out)
    assert len(rows) == 1
    assert data_lines(rows[0]) == ["Artifact: nssVersion: 3.79.0-17.el9_1 Type: rpm"]
    assert rows[0]["severity"] == "high"


def test_max_severity_excludes_critical_member_before_aggregation(tmp_path):
    """The retained row must not inherit a severity the filter excluded."""
    critical = match("nspr", "4.34.0-17.el9_1", severity="Critical")
    low = match("nss", "3.79.0-17.el9_1", severity="Low",
                data_source="https://github.com/advisories/GHSA-test")

    _, out = run_plugin(tmp_path, report([critical, low]), max_severity="med")

    rows = vulns(out)
    assert len(rows) == 1
    assert data_lines(rows[0]) == ["Artifact: nssVersion: 3.79.0-17.el9_1 Type: rpm"]
    assert rows[0]["severity"] == "low"


def test_group_whose_matches_are_all_filtered_leaves_no_row(tmp_path):
    _, out = run_plugin(tmp_path, report([
        match("nspr", "4.34.0-17.el9_1", severity="Negligible"),
        match("nss", "3.79.0-17.el9_1", severity="Negligible"),
    ]), ignore_info=True)

    assert out["hosts"][0]["ip"] == "registry.example.com/keycloak:21.1"
    assert vulns(out) == []


def test_unclassified_severity_ranks_below_low(tmp_path):
    unknown = match("nspr", "4.34.0-17.el9_1", severity="Unknown", related=False)
    low = match("nss", "3.79.0-17.el9_1", severity="Low", related=False)

    _, out = run_plugin(tmp_path, report([unknown, low]))
    rows = vulns(out)
    assert len(rows) == 1
    assert rows[0]["severity"] == "low"
    assert len(data_lines(rows[0])) == 2

    _, filtered = run_plugin(tmp_path, report([unknown, low]), min_severity="info")
    assert [row["severity"] for row in vulns(filtered)] == ["low"]
    assert data_lines(vulns(filtered)[0]) == [
        "Artifact: nssVersion: 3.79.0-17.el9_1 Type: rpm"
    ]


# --------------------------------------------------------------------------- #
# Advisory record variants
# --------------------------------------------------------------------------- #

def test_direct_vulnerability_path_aggregates_components(tmp_path):
    _, out = run_plugin(tmp_path, report([
        match("nspr", "4.34.0-17.el9_1", related=False),
        match("nss", "3.79.0-17.el9_1", related=False),
    ]))

    rows = vulns(out)
    assert len(rows) == 1
    assert rows[0]["desc"] == DESC
    assert len(data_lines(rows[0])) == 2
    assert rows[0]["severity"] == "high"


@pytest.mark.parametrize("metadata,expected", [
    ({"Source": "nss"}, "Artifact: nss [nss] Version: 3.79.0-17.el9_1 Type: rpm"),
    ({"VirtualPath": "/usr/lib64/libnss.so"},
     "Artifact: nss [/usr/lib64/libnss.so] Version: 3.79.0-17.el9_1 Type: rpm"),
])
def test_artifact_metadata_variants_are_preserved_in_data(tmp_path, metadata, expected):
    _, out = run_plugin(tmp_path, report([
        match("nss", "3.79.0-17.el9_1", metadata=metadata),
        match("nspr", "4.34.0-17.el9_1"),
    ]))

    lines = data_lines(vulns(out)[0])
    assert lines[0] == expected
    assert lines[1] == "Artifact: nsprVersion: 4.34.0-17.el9_1 Type: rpm"
    assert len(lines) == 2


# --------------------------------------------------------------------------- #
# Host source branches
# --------------------------------------------------------------------------- #

def test_host_from_image_tags_branch(tmp_path):
    _, out = run_plugin(tmp_path, report(
        [match("nspr"), match("nss")], target_as_string=True,
        tags=["keycloak:21.1"], user_input="keycloak:21.1"))

    host = out["hosts"][0]
    assert host["ip"] == "keycloak:21.1"
    assert host["description"] == "Type: Docker Image"
    assert len(host["vulnerabilities"]) == 1
    assert len(data_lines(host["vulnerabilities"][0])) == 2


def test_host_from_string_source_target(tmp_path):
    _, out = run_plugin(tmp_path, report(
        [match("nspr"), match("nss")], target_as_string=True,
        user_input="/opt/app", source_type="directory"))

    host = out["hosts"][0]
    assert host["ip"] == "/opt/app"
    assert host["description"] == "Type: directory"


# --------------------------------------------------------------------------- #
# Compatibility and summaries
# --------------------------------------------------------------------------- #

def test_single_match_output_is_unchanged(tmp_path):
    _, out = run_plugin(tmp_path, report([match("nspr")]))

    row = vulns(out)[0]
    assert row["name"] == CVE
    assert row["desc"] == DESC
    assert row["severity"] == "high"
    assert row["data"] == "Artifact: nsprVersion: 4.34.0-17.el9_1 Type: rpm"
    assert row["cve"] == [CVE]
    assert row["external_id"] is None
    # dataSource is also the single entry of urls, so a lone match keeps the
    # repeated pair it always produced.
    assert [ref["name"] for ref in row["refs"]] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-12413",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-12413",
    ]
    assert [ref["type"] for ref in row["refs"]] == ["other", "other"]


def test_empty_report_keeps_host(tmp_path):
    _, out = run_plugin(tmp_path, report([]))

    assert out["hosts"][0]["ip"] == "registry.example.com/keycloak:21.1"
    assert out["hosts"][0]["vulnerabilities"] == []


def test_summary_counts_the_single_merged_row(tmp_path):
    plugin, out = run_plugin(tmp_path, report([
        match("nspr", "4.34.0-17.el9_1"),
        match("nss", "3.79.0-17.el9_1"),
        match("nss-util", "3.79.0-17.el9_1"),
    ]))

    summary = plugin.get_summary()
    assert len(vulns(out)) == 1
    assert summary["hosts_vulns"] == 1
    assert summary["severity_vulns"]["high"] == 1
    assert len(summary["vuln_hashes"]) == 1
    assert data_lines(vulns(out)[0]) == out["hosts"][0]["vulnerabilities"][0]["data"].split("\n")

# --------------------------------------------------------------------------- #
# Compatibility regressions for previously untested parser paths
# --------------------------------------------------------------------------- #

def test_links_take_precedence_over_urls_on_related_path(tmp_path):
    """Synthetic boundary input: an advisory record carrying both `links` and
    `urls`. `links` wins, and the union still follows first-seen match order."""
    first = match("nspr", "4.34.0-17.el9_1",
                  data_source="https://nvd.nist.gov/vuln/detail/CVE-2020-12413",
                  related_links=["https://advisories.example/nspr-note"],
                  related_urls=["https://nvd.nist.gov/vuln/detail/CVE-2020-12413",
                                "https://urls-only.example/nspr"])
    second = match("nss", "3.79.0-17.el9_1",
                   data_source="https://github.com/advisories/GHSA-test",
                   related_links=["https://advisories.example/nss-note"],
                   related_urls=["https://github.com/advisories/GHSA-test",
                                 "https://urls-only.example/nss"])

    _, out = run_plugin(tmp_path, report([first, second]))

    rows = vulns(out)
    assert len(rows) == 1
    refs = [ref["name"] for ref in rows[0]["refs"]]
    assert refs == [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-12413",
        "https://advisories.example/nspr-note",
        "https://github.com/advisories/GHSA-test",
        "https://advisories.example/nss-note",
    ]
    assert not any("urls-only.example" in ref for ref in refs)


def test_links_take_precedence_over_urls_on_direct_path(tmp_path):
    entry = match("nss", "3.79.0-17.el9_1", related=False,
                  vuln_urls=["https://urls-only.example/direct"])
    entry["vulnerability"]["links"] = ["https://advisories.example/direct-note"]

    _, out = run_plugin(tmp_path, report([entry]))

    refs = [ref["name"] for ref in vulns(out)[0]["refs"]]
    # The direct path never appended the vulnerability dataSource, and it must
    # still ignore `urls` when `links` is present.
    assert refs == ["https://advisories.example/direct-note"]


def test_empty_related_list_falls_back_to_direct_vulnerability(tmp_path):
    entry = match("nss", "3.79.0-17.el9_1", description="Direct description",
                  severity="Critical")
    entry["relatedVulnerabilities"] = []

    _, out = run_plugin(tmp_path, report([entry]))

    row = vulns(out)[0]
    assert row["desc"] == "Direct description"
    assert row["severity"] == "critical"
    assert [ref["name"] for ref in row["refs"]] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-12413"
    ]


def test_multiple_related_records_use_only_the_first(tmp_path):
    entry = match("nspr", "4.34.0-17.el9_1")
    entry["relatedVulnerabilities"].append({
        "id": "GHSA-second",
        "dataSource": "https://second.example/record",
        "namespace": "nvd:cpe",
        "severity": "Critical",
        "urls": ["https://second.example/url"],
        "description": "A different description that must not win.",
    })

    _, out = run_plugin(tmp_path, report([entry]))

    row = vulns(out)[0]
    assert row["desc"] == DESC
    assert row["severity"] == "high"
    refs = [ref["name"] for ref in row["refs"]]
    assert refs == ["https://nvd.nist.gov/vuln/detail/CVE-2020-12413"] * 2
    assert not any("second.example" in ref for ref in refs)


def test_repeated_parse_of_the_same_report_does_not_duplicate(tmp_path):
    """Re-importing one report on the same plugin must not grow artifacts or rows.
    Aggregation across different reports is not claimed."""
    path = tmp_path / "grype.json"
    path.write_text(json.dumps(report([match("nspr", "4.34.0-17.el9_1"),
                                      match("nss", "3.79.0-17.el9_1")])), encoding="utf-8")
    plugin = GrypePlugin(hostname_resolution=False)

    plugin.processReport(path)
    first = json.loads(plugin.get_json())
    plugin.processReport(path)
    second = json.loads(plugin.get_json())

    assert len(first["hosts"]) == 1 and len(second["hosts"]) == 1
    assert len(vulns(first)) == 1 and len(vulns(second)) == 1
    assert data_lines(vulns(first)[0]) == [
        "Artifact: nsprVersion: 4.34.0-17.el9_1 Type: rpm",
        "Artifact: nssVersion: 3.79.0-17.el9_1 Type: rpm",
    ]
    assert data_lines(vulns(second)[0]) == data_lines(vulns(first)[0])
    assert plugin.get_summary()["hosts_vulns"] == 1


def test_max_severity_keeps_the_highest_eligible_match_only(tmp_path):
    """Synthetic mixed severities: pins per-match filtering under max_severity, so
    the excluded match leaks neither artifact data nor references."""
    unknown = match("nspr", "4.34.0-17.el9_1", severity="Unknown",
                    data_source="https://advisories.example/unknown-artifact")
    high = match("nss", "3.79.0-17.el9_1", severity="High",
                 data_source="https://advisories.example/high-artifact")
    low = match("nss-util", "3.79.0-17.el9_1", severity="Low",
                data_source="https://advisories.example/low-artifact")

    _, out = run_plugin(tmp_path, report([unknown, high, low]), max_severity="med")

    rows = vulns(out)
    assert len(rows) == 1
    assert rows[0]["severity"] == "low"
    assert data_lines(rows[0]) == [
        "Artifact: nsprVersion: 4.34.0-17.el9_1 Type: rpm",
        "Artifact: nss-utilVersion: 3.79.0-17.el9_1 Type: rpm",
    ]
    refs = [ref["name"] for ref in rows[0]["refs"]]
    assert not any("high-artifact" in ref for ref in refs)