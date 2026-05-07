"""
Faraday Penetration Test IDE
Copyright (C) 2018 Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re

from faraday_plugins.plugins.plugin import PluginXMLFormat
from faraday_plugins.plugins.plugins_utils import get_vulnweb_url_fields

import xml.etree.ElementTree as ET


def cleanhtml(raw_html):
    if not raw_html:
        return ""
    cleanr = re.compile('<.*?>')
    return re.sub(cleanr, '', raw_html)


class WebInspectParser():

    def __init__(self, output):
        if isinstance(output, str) and output.startswith("﻿"):
            output = output.lstrip("﻿")
        self.xml = ET.fromstring(output)
        # Two report shapes are in the wild:
        #   * Older:  <Scan> ... <Issues><Issue>... </Scan>
        #   * Newer:  <Sessions><Session>... <Issues><Issue>... </Sessions>
        # In the newer shape each <Issue> inherits URL/Host/Port from its
        # parent <Session>, not from its own children.
        self.session_context = []  # list of (session_element, issue_element)
        if self.xml.tag == "Sessions" or self.xml.find("Session") is not None:
            for session in self.xml.findall(".//Session"):
                for issue in session.findall("Issues/Issue"):
                    self.session_context.append((session, issue))
        # Always populate the plain issue list so the original parsing code
        # (which expects Issue.find("URL") etc.) still works for the legacy
        # shape that does carry those fields directly.
        self.issues = self.xml.findall(".//Issues/Issue")

    def parse_severity(self, severity):

        severity_dict = {
            "0": "info",
            "1": "low",
            "2": "med",
            "3": "high",
            "4": "critical"}

        result = severity_dict.get(severity)
        if not result:
            return "info"
        else:
            return result

    def return_text(self, tag,element):
        try:
            text = element.find(tag).text
            return text
        except:
            return ""

    def parse(self):

        map_objects_fields = {
            "Name": ["Vuln", "name"],
            "URL": ["Vuln", "website"],
            "Scheme": ["Service", "name"],
            "Host": ["Host", "name"],
            "Port": ["Service", "port"],
            "AttackMethod": ["Vuln", "method"],
            "VulnerableSession": ["Vuln", "request"],
            "VulnerabilityID": ["Vuln", "reference"],
            "RawResponse": ["Vuln", "response"],
            "Summary": ["Vuln", "description"],
            "Implication": ["Vuln", "data"],
            "Fix": ["Vuln", "resolution"],
            "Reference Info": ["Vuln", "reference"],
            "Severity": ["Vuln", "severity"]
        }

        result = []
        # Iterate either (session, issue) pairs (new shape) or just issues
        # (legacy shape, with `session=None`).
        if self.session_context:
            iterator = self.session_context
        else:
            iterator = [(None, i) for i in self.issues]

        for session, issue in iterator:

            obj = {
                "Host" : {},
                "Service" : {},
                "Interface" : {},
                "Vuln": {
                    "reference" : []}
            }

            for tag, obj_property in map_objects_fields.items():

                # Some fields belong to the session in the new schema; fall
                # back to the issue when not present.
                value = self.return_text(tag, issue)
                if not value and session is not None:
                    value = self.return_text(tag, session)

                if value is not None:

                    faraday_obj_name = obj_property[0]
                    faraday_field = obj_property[1]
                    if faraday_field == "reference":
                        obj[faraday_obj_name].get("reference").append(value)
                    else:
                        obj[faraday_obj_name].update({faraday_field:value})

            # This for loads Summary, Implication, Fix and Reference
            for section in issue.findall("ReportSection"):

                try:
                    field = section.find("Name").text
                    value = section.find("SectionText").text

                    faraday_obj_name = map_objects_fields.get(field)[0]
                    faraday_field = map_objects_fields.get(field)[1]
                except: # nosec
                    continue

                if faraday_field == "reference" and value != "":
                    obj[faraday_obj_name].get("reference").append(cleanhtml(value))
                else:
                    obj[faraday_obj_name].update({faraday_field:value})

            result.append(obj)
        return result


class WebInspectPlugin(PluginXMLFormat):
    """
    This plugin handles WebInspect reports.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Webinspect"
        self.name = "Webinspect"
        self.plugin_version = "0.0.1"
        self.version = "1.0.0"
        # Both XML shapes need to be auto-detected: the older <Scan> wrapper
        # and the newer <Sessions> top level used by current WebInspect.
        self.identifier_tag = ["Scan", "Sessions"]

    def parseOutputString(self, output):

        parser = WebInspectParser(output)
        vulns = parser.parse()

        for vuln in vulns:

            host_id = self.createAndAddHost(vuln.get("Host").get("name"))
            service_id = self.createAndAddServiceToHost(host_id, vuln.get("Service").get("name"),
                                                        protocol=vuln.get("Service").get("name"),
                                                        ports=[vuln.get("Service").get("port")])

            self.createAndAddVulnWebToService(
                host_id, service_id,
                vuln.get("Vuln").get("name"),
                website=get_vulnweb_url_fields(vuln.get("Vuln").get("website")).get("website"),
                path=get_vulnweb_url_fields(vuln.get("Vuln").get("website")).get("path"),
                query=get_vulnweb_url_fields(vuln.get("Vuln").get("website")).get("query"),
                method=vuln.get("Vuln").get("method"),
                request=vuln.get("Vuln").get("request"),
                ref=list(filter(None ,vuln.get("Vuln").get("reference"))),
                response=vuln.get("Vuln").get("response"),
                desc=cleanhtml(vuln.get("Vuln").get("description")),
                resolution=cleanhtml(vuln.get("Vuln").get("resolution")),
                severity=parser.parse_severity(vuln.get("Vuln").get("severity"))
            )


def createPlugin(*args, **kwargs):
    return WebInspectPlugin(*args, **kwargs)
