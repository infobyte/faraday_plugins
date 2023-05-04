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
            tool = run.get("tool",{}).get("driver",{}).get("name", "")
            for rule in run.get("tool",{}).get("driver",{}).get("rules", []):
                rules[rule["id"]] = rule
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
                    severity = self.map_severity(result.get("level", ""))
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
