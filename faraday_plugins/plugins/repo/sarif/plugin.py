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


    def parseOutputString(self, output):
        """
        This method will discard the output the shell sends, it will read it
        from the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """
        runs = loads(output).get("runs", "")
        for run in runs:
            rules = {}
            tool = (run.get("tool") or {}).get("driver", {}).get("name", "")
            for rule in (run.get("tool") or {}).get("driver", {}).get("rules", []) or []:
                if isinstance(rule, dict) and rule.get("id"):
                    rules[rule["id"]] = rule
            for result in run.get("results", []) or []:
                locations = result.get("locations", []) or []
                # Some SARIF emitters omit locations entirely (e.g. Spotbugs
                # at run level) — fall back to a placeholder host so we still
                # surface the finding.
                if not locations:
                    locations = [{}]
                rule_id = result.get("ruleId")
                rule = rules.get(rule_id) or {}
                # Defensive accessors so missing/None subfields don't crash.
                short_node = rule.get("shortDescription") or {}
                full_node = rule.get("fullDescription") or {}
                help_node = rule.get("help") or {}
                short_description = short_node.get("text") or markdown2text(short_node.get("markdown", "") or "")
                desc = full_node.get("text") or markdown2text(full_node.get("markdown", "") or "")
                help_text = help_node.get("text") or markdown2text(help_node.get("markdown", "") or "")
                # Result-level message is a useful fallback when rule has nothing.
                if not desc:
                    msg_node = result.get("message") or {}
                    desc = msg_node.get("text") or msg_node.get("markdown") or ""
                tags_to_check = (rule.get("properties") or {}).get("tags", []) or []
                cwe = []
                tags = []
                severity = self.map_severity(result.get("level", ""))
                for tag in tags_to_check:
                    if isinstance(tag, str) and "cwe" in tag.lower():
                        cwe.append(tag)
                    elif isinstance(tag, str):
                        tags.append(tag)
                if "Snyk Open Source" == tool.strip():
                    external_id = result.get("ruleId")
                else:
                    external_id = f"{tool} {result.get('ruleId')}".strip()

                name = rule.get("name") or short_description or rule_id or "SARIF finding"

                for location in locations:
                    phys = location.get("physicalLocation") or {}
                    artifact = phys.get("artifactLocation") or {}
                    loc = artifact.get("uri") or "/"
                    h_id = self.createAndAddHost(loc)

                    self.createAndAddVulnToHost(
                        host_id=h_id,
                        name=name,
                        desc=desc,
                        data=help_text,
                        tags=tags,
                        cwe=cwe,
                        severity=severity,
                        external_id=external_id,
                    )


def createPlugin(*args, **kwargs):
    return SarifPlugin(*args, **kwargs)
