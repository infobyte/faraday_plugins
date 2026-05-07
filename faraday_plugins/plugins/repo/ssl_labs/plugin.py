"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json

from faraday_plugins.plugins.plugin import PluginJsonFormat


__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.2.0"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


# Map ssl labs grades / hasWarnings to severity for the overall finding.
GRADE_SEVERITY = {
    "A+": "info", "A": "info", "A-": "info",
    "B": "low", "C": "med", "D": "high", "E": "high", "F": "critical",
    "T": "high",  # certificate not trusted
    "M": "high",  # certificate name mismatch
}


def _add(target_list, name, **kwargs):
    target_list.append({"name": name, **kwargs})


def _details_findings(details):
    """Extract vulnerability findings from endpoint.details (new API schema)."""
    findings = []
    if details.get("vulnBeast"):
        _add(findings, "BEAST attack possible (TLS 1.0 supported)",
             severity="med",
             desc="The server is vulnerable to the BEAST attack against TLS 1.0.",
             ref=["https://www.imperva.com/learn/application-security/beast-attack/"])
    if details.get("heartbleed"):
        _add(findings, "OpenSSL Heartbleed",
             severity="critical",
             desc="The server's OpenSSL is vulnerable to CVE-2014-0160 (Heartbleed).",
             ref=["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"])
    if details.get("openSslCcs") in (2, 3):
        _add(findings, "OpenSSL CCS Injection",
             severity="high",
             desc="The server is vulnerable to CVE-2014-0224 (CCS Injection).",
             ref=["https://nvd.nist.gov/vuln/detail/CVE-2014-0224"])
    if details.get("openSSLLuckyMinus20") == 2:
        _add(findings, "OpenSSL Lucky Minus-20 (CVE-2016-2107)",
             severity="high",
             ref=["https://nvd.nist.gov/vuln/detail/CVE-2016-2107"])
    if details.get("ticketbleed") == 2:
        _add(findings, "Ticketbleed (CVE-2016-9244)",
             severity="med",
             ref=["https://filippo.io/Ticketbleed/"])
    if details.get("bleichenbacher") in (2, 3):
        _add(findings, "Bleichenbacher / ROBOT attack",
             severity="high",
             ref=["https://robotattack.org/"])
    if details.get("zombiePoodle") in (2, 3) or details.get("goldenDoodle") in (2, 3):
        _add(findings, "Zombie/Golden POODLE",
             severity="high",
             ref=["https://www.tripwire.com/state-of-security/security-data-protection/cyber-security/poodle-attack/"])
    if details.get("poodle"):
        _add(findings, "POODLE attack (SSL 3.0)",
             severity="high",
             ref=["https://nvd.nist.gov/vuln/detail/CVE-2014-3566"])
    if details.get("poodleTls") == 2:
        _add(findings, "POODLE attack against TLS",
             severity="high")
    if details.get("freak"):
        _add(findings, "FREAK attack (export-grade RSA)",
             severity="high",
             ref=["https://nvd.nist.gov/vuln/detail/CVE-2015-0204"])
    if details.get("logjam"):
        _add(findings, "Logjam attack (weak DH)",
             severity="high",
             ref=["https://nvd.nist.gov/vuln/detail/CVE-2015-4000"])
    if details.get("drownVulnerable"):
        _add(findings, "DROWN attack",
             severity="high",
             ref=["https://drownattack.com/"])
    if details.get("supportsRc4") and details.get("rc4Only"):
        _add(findings, "RC4-only ciphers", severity="med")
    elif details.get("supportsRc4"):
        _add(findings, "RC4 ciphers supported", severity="low")

    # Weak / deprecated protocols
    weak_protos = []
    for p in details.get("protocols", []) or []:
        ver = (p.get("version") or "").strip()
        name = p.get("name", "TLS")
        if ver in ("1.0", "1.1") or (name == "SSL"):
            weak_protos.append(f"{name} {ver}")
    if weak_protos:
        _add(findings, f"Deprecated protocol(s) supported: {', '.join(weak_protos)}",
             severity="low",
             desc="TLS 1.0 / 1.1 and SSL versions are deprecated and considered insecure.")
    return findings


def _cert_findings(certs):
    """Surface cert-level issues: revoked, expired, weak signature, SHA1, etc."""
    findings = []
    for c in certs or []:
        sub = c.get("subject", "") or ""
        sig = (c.get("sigAlg") or "").lower()
        if sig and ("sha1" in sig or "md5" in sig):
            _add(findings, f"Weak certificate signature ({sig.upper()})",
                 severity="high",
                 desc=f"Certificate {sub} uses {sig}, considered insecure.")
        if c.get("revocationStatus") == 2:
            _add(findings, f"Revoked certificate: {sub}",
                 severity="critical",
                 desc="The certificate is reported as revoked.")
        # issues bitmask: 0x80=expired, 0x100=not yet valid, 0x200=cert mismatch
        issues = c.get("issues") or 0
        if issues & 0x80:
            _add(findings, f"Expired certificate: {sub}", severity="critical")
        if issues & 0x100:
            _add(findings, f"Certificate not yet valid: {sub}", severity="high")
        if issues & 0x200:
            _add(findings, f"Certificate hostname mismatch: {sub}", severity="high")
    return findings


class SslLabsJsonParser:

    def __init__(self, json_output):
        data = json.loads(json_output)
        # The output may be a list (one entry per host) or a single object.
        if isinstance(data, list):
            self.hosts = data
        else:
            self.hosts = [data]


class SslLabsPlugin(PluginJsonFormat):
    """ Handle the SSL Labs tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "ssllabs"
        self.name = "SSL Labs"
        self.plugin_version = "0.2"
        self.version = "3.4.5"
        self.json_keys = [
            {"engineVersion", "criteriaVersion", "endpoints"},
            {"host", "port", "endpoints"},
        ]

    def parseOutputString(self, output):
        parser = SslLabsJsonParser(output)
        for host_data in parser.hosts:
            self._handle_host(host_data)

    def _handle_host(self, host_data):
        host_name = host_data.get("host", "unknown")
        port = host_data.get("port", 443)
        protocol = host_data.get("protocol", "https")
        endpoints = host_data.get("endpoints") or [{}]
        engine_version = host_data.get("engineVersion", "")
        certs = host_data.get("certs") or []

        # Use the first endpoint's IP if available; fall back to hostname.
        ip = (endpoints[0].get("ipAddress") if endpoints else None) or host_name

        host_id = self.createAndAddHost(
            ip,
            hostnames=[host_name],
            description=f"SSL Labs scan, engine {engine_version}",
        )
        service_id = self.createAndAddServiceToHost(
            host_id=host_id,
            name=protocol,
            protocol="tcp",
            ports=port,
            version=engine_version,
        )

        for ep in endpoints:
            grade = ep.get("grade") or ep.get("gradeTrustIgnored") or ""
            details = ep.get("details") or {}
            findings = _details_findings(details)
            findings += _cert_findings(certs)

            if grade and grade not in ("A", "A+", "A-"):
                findings.append({
                    "name": f"SSL Labs grade: {grade}",
                    "severity": GRADE_SEVERITY.get(grade, "low"),
                    "desc": ep.get("statusMessage", "") or
                            f"Endpoint received grade {grade} from SSL Labs.",
                })

            # If we have an IP that differs from our anchor host, attribute findings
            # to the right host record.
            ep_ip = ep.get("ipAddress")
            if ep_ip and ep_ip != ip:
                ep_host_id = self.createAndAddHost(ep_ip, hostnames=[host_name])
                ep_service_id = self.createAndAddServiceToHost(
                    host_id=ep_host_id, name=protocol, protocol="tcp", ports=port,
                )
            else:
                ep_host_id = host_id
                ep_service_id = service_id

            for f in findings:
                self.createAndAddVulnToService(
                    ep_host_id,
                    service_id=ep_service_id,
                    name=f["name"],
                    desc=f.get("desc", ""),
                    severity=f.get("severity", "info"),
                    ref=f.get("ref", []),
                    data=f.get("data", ""),
                )


def createPlugin(*args, **kwargs):
    return SslLabsPlugin(*args, **kwargs)
