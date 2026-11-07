"""Regression tests for Nmap host-script <elem> evidence in the host DTO.

The nmap importer assembles ``script output + "\\nOutput: " + <elem> pairs``
for host scripts.  These tests feed a small valid Nmap XML document straight
into the product (``NmapPlugin.parseOutputString`` -> ``get_json``) and assert
on the host vulnerability ``desc`` that the DTO actually carries.

Only the host-script channel is asserted as evidence-bearing.  Output-only
scripts, scripts with no text at all, and the port-80 web-script channel are
controls: they must keep their existing behaviour, so an unrelated regression
is visible as well.
"""

import json
import unittest

from faraday_plugins.plugins.repo.nmap.plugin import NmapPlugin

NMAPRUN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -A 192.0.2.10" start="1750000000">
<host starttime="1750000000" endtime="1750000010">
<status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="lab.example.test" type="PTR"/></hostnames>
<ports>
{port_nodes}
</ports>
<hostscript>
{script_nodes}
</hostscript>
</host>
</nmaprun>
"""

PORT_80_HTTP_TITLE = """<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.25"/>
<script id="http-title" output="Lab Login"><elem key="title">Lab Login</elem></script>
</port>"""


def parse_host(script_nodes, port_nodes=""):
    """Parse one host with the given host-script and port nodes."""
    plugin = NmapPlugin()
    plugin.parseOutputString(
        NMAPRUN.format(port_nodes=port_nodes, script_nodes=script_nodes).encode("utf-8")
    )
    return json.loads(plugin.get_json())


def host_vuln(dto, name):
    """Return the single host vulnerability called ``name``."""
    matches = [
        vuln for vuln in dto["hosts"][0]["vulnerabilities"] if vuln["name"] == name
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one host vulnerability {name!r}, got {len(matches)}")
    return matches[0]


class HostScriptEvidenceTest(unittest.TestCase):
    def test_host_script_elem_evidence_is_forwarded(self):
        dto = parse_host(
            """<script id="smb-os-discovery" output="OS: Windows Server 2019 Standard 17763">
<elem key="os">Windows Server 2019 Standard 17763</elem>
<elem key="computer_name">LABHOST</elem>
<elem key="workgroup">LAB</elem>
</script>"""
        )
        vuln = host_vuln(dto, "smb-os-discovery")
        desc = vuln["desc"]
        self.assertTrue(desc.startswith("OS: Windows Server 2019 Standard 17763"))
        self.assertIn("Output:", desc)
        self.assertIn("os: Windows Server 2019 Standard 17763", desc)
        self.assertIn("computer_name: LABHOST", desc)
        self.assertIn("workgroup: LAB", desc)

    def test_each_direct_elem_key_is_kept(self):
        dto = parse_host(
            """<script id="clock-skew" output="mean: 0s, deviation: 0s, max: 0s">
<elem key="count">4</elem>
<elem key="mean">0</elem>
</script>"""
        )
        vuln = host_vuln(dto, "clock-skew")
        self.assertIn("count: 4", vuln["desc"])
        self.assertIn("mean: 0", vuln["desc"])

    def test_output_only_host_script_keeps_output_without_marker(self):
        output = "OS: Linux 5.10"
        dto = parse_host(f'<script id="smb-os-discovery" output="{output}"/>')
        vuln = host_vuln(dto, "smb-os-discovery")
        self.assertEqual(vuln["desc"], output)
        self.assertNotIn("Output:", vuln["desc"])

    def test_script_without_output_adds_no_marker(self):
        dto = parse_host('<script id="nbstat" output=""/>')
        vuln = host_vuln(dto, "nbstat")
        self.assertEqual(vuln["desc"], "")
        self.assertNotIn("Output:", vuln["desc"])

    def test_port_80_web_script_keeps_its_response_channel(self):
        dto = parse_host("", port_nodes=PORT_80_HTTP_TITLE)
        service = dto["hosts"][0]["services"][0]
        vuln = service["vulnerabilities"][0]
        self.assertEqual(vuln["desc"], "Lab Login")
        self.assertEqual(vuln["response"], "\ntitle: Lab Login")


if __name__ == "__main__":
    unittest.main()
