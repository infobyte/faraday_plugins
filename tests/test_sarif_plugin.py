"""Regression tests for SARIF effective severity (result level resolution).

Semantics under test come from the OASIS SARIF v2.1.0 standard; section
numbers below refer to that document:
  3.27.9/3.27.10: kind/level defaults, kind != "fail" -> "none", and the
      fail/absent-level procedure (override -> defaultConfiguration -> warning);
  3.48.6: invocationIndex defaults (single invocation -> 0, otherwise unknown);
  3.51.2/3.51.3: override descriptor matching and per-property inheritance;
  3.52.2-3.52.7: descriptor identity is index and/or guid only (id and name do
      not participate), and toolComponent absent => driver;
  3.54.2-3.54.5: toolComponent lookup (index => tool.extensions, guid =>
      the component with that guid, name does not participate);
  3.7.4: array indices are zero-based; -1 is the schema's "unknown" default.

Reports are built in memory and pushed through the real SarifPlugin
(parseOutputString -> createAndAddVulnToHost -> its own filter -> get_data).
Nothing here talks to the network, and no hostname is resolved by the importer.
"""
import json

import pytest

from faraday_plugins.plugins.repo.sarif.plugin import SarifPlugin

TOOL = "sarif-effective-fixtures"
DRIVER_GUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RULE_GUID = "bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb"
OTHER_RULE_GUID = "cccccccc-cccc-4ccc-accc-cccccccccccc"
EXTENSION_GUID = "dddddddd-dddd-4ddd-bddd-dddddddddddd"
EXPLICIT = {"error": "high", "warning": "med", "note": "low", "none": "unclassified"}


def rule(rule_id, default_level=None, guid=None, tags=("security", "cwe-79"), **extra):
    descriptor = {
        "id": rule_id,
        "name": "%s_name" % rule_id,
        "shortDescription": {"text": "%s short" % rule_id},
        "fullDescription": {"text": "%s full" % rule_id},
        "help": {"text": "%s help" % rule_id},
        "properties": {"tags": list(tags)},
    }
    if default_level is not None:
        descriptor["defaultConfiguration"] = {"level": default_level}
    if guid is not None:
        descriptor["guid"] = guid
    descriptor.update(extra)
    return descriptor


def result(rule_id, rule_index=0, level=None, kind=None, path=None):
    item = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "message": {"text": "%s message" % rule_id},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": path or "src/%s.py" % rule_id},
            "region": {"startLine": 1},
        }}],
    }
    if level is not None:
        item["level"] = level
    if kind is not None:
        item["kind"] = kind
    return item


def reference(**fields):
    """A reportingDescriptorReference with exactly the given identity fields."""
    return dict(fields)


def override(ref, level=None, extra_config=None):
    configuration = dict(extra_config or {})
    if level is not None:
        configuration["level"] = level
    return {"descriptor": ref, "configuration": configuration}


def invocation(overrides=None):
    return {"executionSuccessful": True, "ruleConfigurationOverrides": overrides or []}


def extension(rules, name="sarif-effective-extension", guid=EXTENSION_GUID):
    return {"name": name, "guid": guid, "rules": rules}


def run(rules, results, invocations=None, driver_extra=None, extensions=None):
    driver = {"name": TOOL, "informationUri": "https://example.invalid/tool", "rules": rules}
    if driver_extra:
        driver.update(driver_extra)
    tool = {"driver": driver}
    if extensions is not None:
        tool["extensions"] = extensions
    run_obj = {"tool": tool, "results": results}
    if invocations is not None:
        run_obj["invocations"] = invocations
    return run_obj


def report(*runs):
    return {"version": "2.1.0", "runs": list(runs)}


def import_report(document, **plugin_kwargs):
    plugin = SarifPlugin(**plugin_kwargs)
    plugin.parseOutputString(json.dumps(document))
    return plugin.get_data()


def findings(data):
    return [vuln for host in data["hosts"] for vuln in host["vulnerabilities"]]


def severities(document, **plugin_kwargs):
    return [v["severity"] for v in findings(import_report(document, **plugin_kwargs))]


# --- explicit level wins over every default ---------------------------------

@pytest.mark.parametrize("rule_default", ["error", "warning", "note", "none"])
@pytest.mark.parametrize("explicit", ["error", "warning", "note", "none"])
def test_explicit_level_wins_over_conflicting_rule_default(explicit, rule_default):
    doc = report(run([rule("R1", default_level=rule_default)],
                     [result("R1", level=explicit, path="src/explicit_%s_%s.py" % (explicit, rule_default))]))
    assert severities(doc) == [EXPLICIT[explicit]]


# --- absent level on a failing result --------------------------------------

@pytest.mark.parametrize("rule_default,expected", [
    ("error", "high"),
    ("warning", "med"),
    ("note", "low"),
    ("none", "unclassified"),
])
def test_absent_level_uses_rule_default(rule_default, expected):
    doc = report(run([rule("R1", default_level=rule_default)], [result("R1")]))
    assert severities(doc) == [expected]


def test_absent_level_without_any_rule_default_falls_back_to_warning():
    doc = report(run([rule("R1")], [result("R1")]))
    assert severities(doc) == ["med"]


def test_absent_level_with_empty_default_configuration_falls_back_to_warning():
    descriptor = rule("R1")
    descriptor["defaultConfiguration"] = {}
    doc = report(run([descriptor], [result("R1")]))
    assert severities(doc) == ["med"]


# --- non-failing kinds never become severity findings ----------------------

@pytest.mark.parametrize("kind", ["pass", "open", "informational", "notApplicable", "review"])
def test_nonfail_kind_defaults_level_to_none(kind):
    doc = report(run([rule("R1", default_level="error")], [result("R1", kind=kind)]))
    assert severities(doc) == ["unclassified"]


def test_absent_kind_is_treated_as_fail():
    doc = report(run([rule("R1", default_level="error")], [result("R1", kind=None)]))
    assert severities(doc) == ["high"]


def test_explicit_none_with_informational_kind_stays_unclassified():
    # Valid contract control: a non-fail kind may carry level "none" (3.27.9).
    doc = report(run([rule("R1", default_level="error")],
                     [result("R1", kind="informational", level="none")]))
    assert severities(doc) == ["unclassified"]


def test_nonfail_kind_ignores_an_applicable_invocation_override():
    invs = [invocation([override(reference(index=0), "note")])]
    doc = report(run([rule("R1", default_level="error")],
                     [result("R1", kind="informational")], invocations=invs))
    assert severities(doc) == ["unclassified"]


# --- invocation override with descriptor identity ---------------------------

def _override_severity(ref_fields, rule_kwargs=None, driver_extra=None,
                       extensions=None, extra_rules=()):
    rules = [rule("R1", default_level="error", **(rule_kwargs or {}))]
    rules.extend(extra_rules)
    invs = [invocation([override(reference(**ref_fields), "note")])]
    doc = report(run(rules, [result("R1")], invocations=invs,
                     driver_extra=driver_extra, extensions=extensions))
    return severities(doc)


def test_matched_override_without_level_inherits_rule_default():
    # 3.51.3: an override that does not set level leaves the descriptor's
    # defaultConfiguration.level in force (enabled:false only here).
    rules = [rule("R1", default_level="error", guid=RULE_GUID)]
    invs = [invocation([override(reference(index=0, guid=RULE_GUID), None, {"enabled": False})])]
    doc = report(run(rules, [result("R1")], invocations=invs))
    assert severities(doc) == ["high"]


def test_override_without_level_and_no_rule_default_falls_back_to_warning():
    invs = [invocation([override(reference(index=0), None, {"enabled": False})])]
    doc = report(run([rule("R1")], [result("R1")], invocations=invs))
    assert severities(doc) == ["med"]


def test_override_for_another_existing_rule_index_does_not_touch_r1():
    # OTHER really exists at index 1: a valid reference that is simply not R1.
    rules = [rule("R1", default_level="error"), rule("OTHER", default_level="error")]
    invs = [invocation([override(reference(index=1), "note")])]
    doc = report(run(rules, [result("R1", rule_index=0)], invocations=invs))
    assert severities(doc) == ["high"]


def test_explicit_result_level_outranks_applicable_invocation_override():
    rules = [rule("R1", default_level="note", guid=RULE_GUID)]
    invs = [invocation([override(reference(index=0, guid=RULE_GUID), "none")])]
    doc = report(run(rules, [result("R1", level="error")], invocations=invs))
    assert severities(doc) == ["high"]


@pytest.mark.parametrize("ref_fields,rule_kwargs,expected", [
    pytest.param({"id": "R1", "index": 0}, {}, "low", id="id_and_index"),
    pytest.param({"index": 0}, {}, "low", id="index_only"),
    pytest.param({"guid": RULE_GUID.upper()}, {"guid": RULE_GUID}, "low", id="guid_only_uppercase"),
    pytest.param({"index": 0, "guid": RULE_GUID}, {"guid": RULE_GUID}, "low", id="index_and_guid_consistent"),
    pytest.param({"index": 1, "guid": RULE_GUID}, {"guid": RULE_GUID}, "high",
                 id="robustness_dangling_inconsistent_index_and_guid"),
    pytest.param({"index": -1, "guid": RULE_GUID}, {"guid": RULE_GUID}, "low", id="index_minus_one_with_guid"),
    pytest.param({"index": -1}, {}, "high", id="robustness_unknown_index_alone"),
])
def test_override_descriptor_identity(ref_fields, rule_kwargs, expected):
    assert _override_severity(ref_fields, rule_kwargs) == [expected]


def test_override_guid_for_a_different_existing_driver_rule_is_not_applied():
    # The referenced guid exists, but it belongs to OTHER, not to R1 (3.52.2).
    other = rule("OTHER", default_level="note", guid=OTHER_RULE_GUID)
    assert _override_severity({"guid": OTHER_RULE_GUID}, {"guid": RULE_GUID},
                              extra_rules=[other]) == ["high"]


def test_robustness_override_guid_not_present_on_the_rule_is_not_applied():
    # Prose-invalid reference (the guid identifies no descriptor in the run).
    assert _override_severity({"guid": RULE_GUID}) == ["high"]


# --- toolComponent scope (3.54.2): driver vs a real extension ---------------

@pytest.mark.parametrize("ref_fields,driver_guid,expected", [
    pytest.param({"index": 0, "toolComponent": {"index": 0}}, DRIVER_GUID, "high",
                 id="real_extension_index"),
    pytest.param({"index": 0, "toolComponent": {"guid": EXTENSION_GUID}}, DRIVER_GUID, "high",
                 id="extension_guid"),
    pytest.param({"index": 0, "toolComponent": {"guid": DRIVER_GUID.upper()}}, DRIVER_GUID, "low",
                 id="driver_guid_uppercase"),
    pytest.param({"index": 0, "toolComponent": {"index": -1, "guid": DRIVER_GUID}}, DRIVER_GUID, "low",
                 id="tolerance_unknown_index_with_driver_guid"),
    pytest.param({"index": 0, "toolComponent": {"index": -1}}, DRIVER_GUID, "low",
                 id="tolerance_unknown_index_is_absence_equivalent"),
])
def test_override_component_scope(ref_fields, driver_guid, expected):
    # The extension holds a rule with the same textual id: it must not be
    # confused with the driver rule of the same id. The two "tolerance_*" ids
    # are schema-allowed -1 sentinels, but 3.54.4 says a driver component's
    # index SHALL be absent, so they are tolerance, not proven legal input.
    exts = [extension([rule("R1", default_level="note")])]
    driver_extra = {"guid": driver_guid} if driver_guid else None
    assert _override_severity(ref_fields, driver_extra=driver_extra,
                              extensions=exts) == [expected]


# --- invocation selection (3.48.6) -----------------------------------------

def _two_invocation_doc():
    rules = [rule("R1", default_level="error")]
    invs = [invocation([override(reference(index=0), "none")]),
            invocation([override(reference(index=0), "note")])]
    return report(run(rules, [result("R1")], invocations=invs))


@pytest.mark.parametrize("provenance,expected", [
    pytest.param({}, "high", id="absent_two_invocations"),
    pytest.param({"provenance": {"invocationIndex": 0}}, "unclassified", id="zero_selects_first"),
    pytest.param({"provenance": {"invocationIndex": 1}}, "low", id="one_selects_second"),
    pytest.param({"provenance": {"invocationIndex": -1}}, "high", id="minus_one_unknown"),
    pytest.param({"provenance": {"invocationIndex": 5}}, "high", id="out_of_range"),
])
def test_invocation_index_selection(provenance, expected):
    doc = _two_invocation_doc()
    doc["runs"][0]["results"][0].update(provenance)
    assert severities(doc) == [expected]


def test_single_invocation_defaults_index_zero():
    invs = [invocation([override(reference(index=0), "note")])]
    doc = report(run([rule("R1", default_level="error")], [result("R1")], invocations=invs))
    assert severities(doc) == ["low"]


def test_multiple_invocations_without_index_do_not_apply_arbitrary_override():
    assert severities(_two_invocation_doc()) == ["high"]


def test_absent_and_empty_invocations_never_apply_overrides():
    rules = [rule("R1", default_level="error")]
    no_invocations = report(run(rules, [result("R1")]))
    empty_invocations = report(run(rules, [result("R1")], invocations=[]))
    assert severities(no_invocations) == ["high"]
    assert severities(empty_invocations) == ["high"]


# --- robustness inputs (schema- or prose-invalid; pinned, not contract) -----

def test_robustness_invocation_index_bool_is_not_usable_as_index():
    doc = _two_invocation_doc()
    doc["runs"][0]["results"][0]["provenance"] = {"invocationIndex": True}
    assert severities(doc) == ["high"]


def test_robustness_invocation_index_string_is_not_usable_as_index():
    doc = _two_invocation_doc()
    doc["runs"][0]["results"][0]["provenance"] = {"invocationIndex": "1"}
    assert severities(doc) == ["high"]


def test_robustness_explicit_null_invocation_index_is_unknown_not_absent():
    # An explicit JSON null is not an absent key: it must not be defaulted to
    # index 0 even when the run holds exactly one invocation.
    invs = [invocation([override(reference(index=0), "note")])]
    doc = report(run([rule("R1", default_level="error")], [result("R1")], invocations=invs))
    doc["runs"][0]["results"][0]["provenance"] = {"invocationIndex": None}
    assert severities(doc) == ["high"]


def test_robustness_explicit_null_invocation_index_with_two_invocations():
    doc = _two_invocation_doc()
    doc["runs"][0]["results"][0]["provenance"] = {"invocationIndex": None}
    assert severities(doc) == ["high"]


def test_robustness_name_only_descriptor_reference_has_no_identity():
    # Schema-valid (id is present) but prose-invalid: name is not identity.
    invs = [invocation([override(reference(id="R1", toolComponent={"name": TOOL}), "note")])]
    doc = report(run([rule("R1", default_level="error")], [result("R1")], invocations=invs))
    assert severities(doc) == ["high"]


def test_robustness_explicit_none_with_fail_kind_is_tolerated():
    # Ambiguous producer output (3.27.9 wants kind informational for "none");
    # pinned as tolerated pass-through rather than asserted as a contract.
    doc = report(run([rule("R1", default_level="error")], [result("R1", level="none")]))
    assert severities(doc) == ["unclassified"]


# --- multi-run isolation ----------------------------------------------------

def test_multi_run_same_rule_id_does_not_leak_configuration():
    doc = report(
        run([rule("R1", default_level="error")], [result("R1", path="src/mr_a.py")]),
        run([rule("R1", default_level="note")], [result("R1", path="src/mr_b.py")]),
    )
    assert severities(doc) == ["high", "low"]


# --- interaction with the importer's own filtering --------------------------

def _error_default_doc(path="src/filter.py"):
    return report(run([rule("R1", default_level="error")], [result("R1", path=path)]))


def test_rule_error_default_survives_ignore_info_and_min_med():
    assert severities(_error_default_doc(), ignore_info=True) == ["high"]
    assert severities(_error_default_doc(), min_severity="med") == ["high"]


def test_rule_error_default_is_dropped_by_max_med():
    assert severities(_error_default_doc(), max_severity="med") == []


def test_rule_note_default_is_excluded_by_min_med():
    doc = report(run([rule("R1", default_level="note")], [result("R1")]))
    assert severities(doc, min_severity="med") == []


def test_all_filtered_report_keeps_hosts_but_no_findings():
    data = import_report(_error_default_doc(), max_severity="low")
    assert findings(data) == []
    assert len(data["hosts"]) == 1


# --- compatibility of the already-supported explicit path -------------------

def test_explicit_level_payload_is_unchanged():
    doc = report(run([rule("R1", default_level="note")], [result("R1", level="error")]))
    (vuln,) = findings(import_report(doc))
    assert vuln == {
        "name": "R1_name",
        "desc": "R1 full",
        "severity": "high",
        "refs": [],
        "external_id": "%s R1" % TOOL,
        "type": "Vulnerability",
        "resolution": "",
        "data": "R1 help",
        "custom_fields": {},
        "status": "open",
        "impact": {},
        "policyviolations": [],
        "cve": [],
        "cvss3": {},
        "cvss2": {},
        "confirmed": False,
        "easeofresolution": None,
        "tags": ["security"],
        "cwe": [],
        "cvss4": {},
    }


def test_reimport_of_same_report_stays_deduplicated():
    plugin = SarifPlugin()
    payload = json.dumps(_error_default_doc("src/dedup.py"))
    plugin.parseOutputString(payload)
    plugin.parseOutputString(payload)
    data = plugin.get_data()
    assert len(findings(data)) == 1
    assert len(data["hosts"]) == 1
