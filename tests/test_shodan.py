import json
from unittest.mock import Mock

from faraday_plugins.plugins.repo.shodan.plugin import ShodanPlugin


def test_shodan_preserves_cvss_score_and_derives_severity():
    plugin = ShodanPlugin()
    plugin.createAndAddHost = Mock(return_value="host-id")
    plugin.createAndAddServiceToHost = Mock(return_value="service-id")
    plugin.createAndAddVulnToService = Mock()

    plugin.parseOutputString(json.dumps({
        "ip_str": "203.0.113.10",
        "port": 443,
        "transport": "tcp",
        "hostnames": ["example.test"],
        "vulns": {
            "CVE-2024-12345": {
                "summary": "Example Shodan vulnerability",
                "references": ["https://example.test/CVE-2024-12345"],
                "cvss": 7.5,
            },
        },
    }))

    plugin.createAndAddVulnToService.assert_called_once()
    args, kwargs = plugin.createAndAddVulnToService.call_args
    assert args[:3] == ("host-id", "service-id", "CVE-2024-12345")
    assert kwargs["severity"] == "high"
    assert kwargs["cvss2"] == {"base_score": 7.5}
    assert kwargs["cve"] == "CVE-2024-12345"
