"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from faraday_plugins.plugins.plugin import PluginJsonFormat
from faraday_plugins.plugins.plugins_utils import markdown2text

from json import loads

__author__ = "Gonzalo Martinez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Gonzalo Martinez"]
__version__ = "1.0.0"
__maintainer__ = "Gonzalo Martinez"
__email__ = "gmartinez@infobytesec.com"
__status__ = "Development"



class SarifPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Sarif"
        self.name = "Sarif Plugin"
        self.plugin_version = "1"
        self.version = "1"
        self.json_keys = {'version'}
        self.framework_version = "1.0.0"
        self.extension = ".sarif"

    def map_severity(self, level):
        mapping = {
            "none": "unclassified",
            "note": "low",
            "warning": "medium",
            "error": "high"
        }
        return mapping.get(level, "")

    @staticmethod
    def _known_index(value):
        """Return a real zero-based array index, else None.

        SARIF 2.1.0 section 3.7.4: array indices are zero-based; the schema
        default and minimum for both reportingDescriptorReference.index and
        toolComponentReference.index is -1, which means unknown (not set). An
        unknown index is absence-equivalent, never a Python list position, and
        a JSON boolean must not be usable as an index.
        """
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return None
        return value

    def _descriptor_ref_matches_driver_rule(self, reference, rule, rule_index, driver):
        """Whether a reportingDescriptorReference identifies this driver rule.

        SARIF 2.1.0 sections 3.52.3, 3.52.5-3.52.7 and 3.54.2: the reference
        resolves inside the component named by toolComponent (absent => driver,
        a real index => tool extension, guid => the component with that guid),
        and descriptor identity is index and/or guid only. Names and ids are not
        identity, and the -1 "unknown" index sentinel is treated as absent.
        """
        component = reference.get("toolComponent")
        if isinstance(component, dict):
            if self._known_index(component.get("index")) is not None:
                return False
            component_guid = component.get("guid")
            if component_guid is not None:
                driver_guid = driver.get("guid")
                if driver_guid is None or str(driver_guid).lower() != str(component_guid).lower():
                    return False
        index = self._known_index(reference.get("index"))
        guid = reference.get("guid")
        if index is None and guid is None:
            return False
        if index is not None and index != rule_index:
            return False
        if guid is not None:
            rule_guid = rule.get("guid")
            if rule_guid is None or str(rule_guid).lower() != str(guid).lower():
                return False
        return True

    def _result_invocation(self, run, result):
        """Invocation selected by result.provenance.invocationIndex (section 3.48.6).

        An absent index defaults to 0 only when the run has exactly one
        invocation; an explicit null, -1, non-integer or out-of-range value
        stays unknown so that no arbitrary invocation override is applied.
        """
        invocations = run.get("invocations")
        if not isinstance(invocations, list) or not invocations:
            return None
        provenance = result.get("provenance")
        if isinstance(provenance, dict) and "invocationIndex" in provenance:
            index = provenance["invocationIndex"]
            if index is None or isinstance(index, bool) or not isinstance(index, int) or index < 0:
                self.logger.warning("SARIF invocationIndex %r is not a valid index; ignoring overrides", index)
                return None
        else:
            if len(invocations) != 1:
                return None
            index = 0
        if index >= len(invocations):
            self.logger.warning("SARIF invocationIndex %r is out of range; ignoring overrides", index)
            return None
        return invocations[index]

    def _effective_level(self, run, result, rule, rule_index, driver):
        """Effective level of a result per SARIF 2.1.0 section 3.27.10.

        An explicit level always wins. A kind other than "fail" defaults to
        "none". For a failing result without a level the procedure is: matching
        invocation ruleConfigurationOverrides level, else the rule
        defaultConfiguration level, else "warning".
        """
        level = result.get("level")
        if level:
            return level
        if result.get("kind", "fail") != "fail":
            return "none"
        invocation = self._result_invocation(run, result)
        if invocation is not None:
            for configuration_override in invocation.get("ruleConfigurationOverrides") or []:
                reference = configuration_override.get("descriptor") or {}
                if not self._descriptor_ref_matches_driver_rule(reference, rule, rule_index, driver):
                    continue
                override_level = (configuration_override.get("configuration") or {}).get("level")
                if override_level:
                    return override_level
                # A matched override without a level respects defaultConfiguration (section 3.51.3).
                break
        default_level = (rule.get("defaultConfiguration") or {}).get("level")
        if default_level:
            return default_level
        return "warning"

    def parseOutputString(self, output):
        """
        This method will discard the output the shell sends, it will read it
        from the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """
        runs = loads(output).get("runs", "")
        for run in runs:
            driver = run.get("tool",{}).get("driver",{})
            tool = driver.get("name", "")
            rules = {}
            rule_indexes = {}
            for rule_index, rule in enumerate(driver.get("rules", [])):
                rules[rule["id"]] = rule
                rule_indexes[rule["id"]] = rule_index
            for result in run.get("results", []):
                locations = result.get("locations",[])
                for location in locations:
                    loc = location.get("physicalLocation", {}).get("artifactLocation").get("uri")
                    if not loc:
                        loc = "/"
                    h_id = self.createAndAddHost(loc)
                    rule  = rules[result.get("ruleId")]
                    name = rule.get("name")
                    short_description = rule.get("shortDescription").get("text") if \
                        rule.get("shortDescription", {}).get("text") else \
                        markdown2text(rule.get("shortDescription", {}).get("markdown", ""))
                    desc = rule.get("fullDescription").get("text") if rule.get("fullDescription", {}).get("text") \
                        else markdown2text(rule.get("fullDescription").get("markdown", ""))
                    help = rule.get("help",{}).get("text") if rule.get("help",{}).get("text") \
                        else markdown2text(rule.get("help",{}).get("markdown", ""))
                    tags_to_check = rule.get("properties",{}).get("tags", [])
                    cwe = []
                    tags = []
                    severity = self.map_severity(self._effective_level(
                        run, result, rule, rule_indexes.get(result.get("ruleId")), driver))
                    for tag in tags_to_check:
                        if "cwe" in tag.lower():
                            cwe.append(tag)
                        else:
                            tags.append(tag)
                    if "Snyk Open Source" == tool.strip():
                        external_id = result.get('ruleId')
                    else:
                        external_id = f"{tool} {result.get('ruleId')}"

                    self.createAndAddVulnToHost(
                        host_id=h_id,
                        name=name if name else short_description,
                        desc=desc,
                        data=help,
                        tags=tags,
                        cwe=cwe,
                        severity=severity,
                        external_id=external_id
                    )


def createPlugin(*args, **kwargs):
    return SarifPlugin(*args, **kwargs)
