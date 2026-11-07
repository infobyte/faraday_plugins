"""Host OS precedence in the Nmap XML importer.

Host-level OS evidence (an ``<os><osclass>`` or a nested
``<osmatch><osclass>``) carries vendor, family, generation and accuracy.  The
importer must expose that value in the ``os`` field of the host DTO and must
not replace it with the low-confidence ``ostype`` attribute of a port
service.

``GENUINE_SCANME_REPORT`` embeds the host record of a genuine recorded scan
(Nmap 5.59BETA3, scanme.nmap.org) byte-for-byte; the other reports are
minimal documents built from the documented Nmap XML DTD elements.  These
tests run no scan, open no socket and contact nothing.
"""

import json

from faraday_plugins.plugins.repo.nmap.plugin import NmapPlugin

GENUINE_SCANME_REPORT = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -T4 -A -p 1-1000 -oX - scanme.nmap.org" version="5.59BETA3" xmloutputversion="1.03">
 <host starttime="1315618421" endtime="1315618434">
  <status state="up" reason="echo-reply"/>
  <address addr="74.207.244.221" addrtype="ipv4"/>
  <hostnames>
   <hostname name="scanme.nmap.org" type="user"/>
   <hostname name="li86-221.members.linode.com" type="PTR"/>
  </hostnames>
  <ports>
   <extraports state="closed" count="997">
    <extrareasons reason="resets" count="997"/>
   </extraports>
   <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack" reason_ttl="53"/>
    <service name="ssh" product="OpenSSH" version="5.3p1 Debian 3ubuntu7"
             extrainfo="protocol 2.0" ostype="Linux" method="probed" conf="10">
     <cpe>cpe:/a:openbsd:openssh:5.3p1</cpe>
     <cpe>cpe:/o:linux:kernel</cpe>
    </service>
    <script id="ssh-hostkey"
            output="1024 8d:60:f1:7c:ca:b7:3d:0a:d6:67:54:9d:69:d9:b9:dd (DSA)&#xa;
                    2048 79:f8:09:ac:d4:e2:32:42:10:49:d3:bd:20:82:85:ec (RSA)"/>
   </port>
   <port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack" reason_ttl="53"/>
    <service name="http" product="Apache httpd" version="2.2.14"
             extrainfo="(Ubuntu)" method="probed" conf="10">
     <cpe>cpe:/a:apache:http_server:2.2.14</cpe>
    </service>
    <script id="http-title" output="Go ahead and ScanMe!"/>
   </port>
  </ports>
  <os>
   <portused state="open" proto="tcp" portid="22"/>
   <portused state="closed" proto="tcp" portid="1"/>
   <portused state="closed" proto="udp" portid="31289"/>
   <osclass type="general purpose" vendor="Linux" osfamily="Linux"
            osgen="2.6.X" accuracy="100">
    <cpe>cpe:/o:linux:linux_kernel:2.6.39</cpe>
   </osclass>
   <osmatch name="Linux 2.6.39" accuracy="100" line="39278"/>
  </os>
  <uptime seconds="23450" lastboot="Fri Sep  9 12:03:04 2011"/>
  <distance value="11"/>
  <tcpsequence index="199" difficulty="Good luck!"
               values="49018209,48C3EBED,495A2E7F,493EF30C,48ED43B3,495A9B0C"/>
  <ipidsequence class="All zeros" values="0,0,0,0,0,0"/>
  <tcptssequence class="1000HZ"
                 values="165CC09,165CC6E,165CCD2,165CD36,165CD9A,165CE48"/>
  <trace port="256" proto="tcp">
   <!-- Several hop elements removed for brevity -->
   <hop ttl="9" ipaddr="72.52.92.109" rtt="15.69" host="10gigabitethernet1-1.core1.fmt1.he.net"/>
   <hop ttl="10" ipaddr="64.62.250.6" rtt="12.06" host="linode-llc.10gigabitethernet2-3.core1.fmt1.he.net"/>
   <hop ttl="11" ipaddr="74.207.244.221" rtt="16.55" host="li86-221.members.linode.com"/>
  </trace>
  <times srtt="26517" rttvar="19989" to="106473"/>
 </host>
</nmaprun>
"""

OSMATCH_REPORT = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -O --osscan-guess -sV -p 22 10.20.30.40" version="7.94" xmloutputversion="1.05">
 <host starttime="1700000000" endtime="1700000060">
  <status state="up" reason="syn-ack"/>
  <address addr="10.20.30.40" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="8.0" extrainfo="Ubuntu Linux" ostype="Linux"
             method="probed" conf="10">
     <cpe>cpe:/a:openbsd:openssh:8.0</cpe>
    </service>
   </port>
  </ports>
  <os>
   <portused state="open" proto="tcp" portid="22"/>
   <osmatch name="Microsoft Windows Server 2008 R2" accuracy="96" line="1">
    <osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2008" accuracy="96">
     <cpe>cpe:/o:microsoft:windows_server_2008</cpe>
    </osclass>
   </osmatch>
  </os>
 </host>
</nmaprun>
"""

OSCLASS_ONLY_REPORT = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -O -p 80 10.20.30.41" version="7.94" xmloutputversion="1.05">
 <host starttime="1700000100" endtime="1700000160">
  <status state="up" reason="syn-ack"/>
  <address addr="10.20.30.41" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack"/>
    <service name="http" product="Microsoft IIS httpd" version="6.0" method="probed" conf="10"/>
   </port>
  </ports>
  <os>
   <osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2003" accuracy="96">
    <cpe>cpe:/o:microsoft:windows_server_2003</cpe>
   </osclass>
  </os>
 </host>
</nmaprun>
"""

NO_OS_SERVICE_OSTYPE_REPORT = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -p 22 10.20.30.42" version="7.94" xmloutputversion="1.05">
 <host starttime="1700000200" endtime="1700000260">
  <status state="up" reason="syn-ack"/>
  <address addr="10.20.30.42" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="7.4" ostype="Linux" method="probed" conf="10"/>
   </port>
  </ports>
 </host>
</nmaprun>
"""

NO_OS_NO_OSTYPE_REPORT = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -p 443 10.20.30.43" version="7.94" xmloutputversion="1.05">
 <host starttime="1700000300" endtime="1700000360">
  <status state="up" reason="syn-ack"/>
  <address addr="10.20.30.43" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="443">
    <state state="open" reason="syn-ack"/>
    <service name="https" method="table" conf="3"/>
   </port>
  </ports>
 </host>
</nmaprun>
"""

EMPTY_HOST_REPORT = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sn 10.20.30.44" version="7.94" xmloutputversion="1.05">
 <host starttime="1700000400" endtime="1700000460">
  <status state="up" reason="echo-reply"/>
  <address addr="10.20.30.44" addrtype="ipv4"/>
 </host>
</nmaprun>
"""


def _host_dtos(report):
    plugin = NmapPlugin()
    plugin.parseOutputString(report.encode("utf-8"))
    return json.loads(plugin.get_json())["hosts"]


def test_genuine_host_keeps_osclass_over_service_ostype():
    """Recorded host: <osclass> Linux/Linux/2.6.X (accuracy 100) + ostype Linux."""
    hosts = _host_dtos(GENUINE_SCANME_REPORT)
    assert hosts[0]["ip"] == "74.207.244.221"
    assert [service["port"] for service in hosts[0]["services"]] == [22, 80]
    assert hosts[0]["os"] == "Linux Linux 2.6.X"


def test_nested_osmatch_osclass_keeps_precedence_over_service_ostype():
    hosts = _host_dtos(OSMATCH_REPORT)
    assert hosts[0]["ip"] == "10.20.30.40"
    assert hosts[0]["os"] == "Microsoft Windows 2008"


def test_osclass_without_service_ostype_is_unchanged():
    hosts = _host_dtos(OSCLASS_ONLY_REPORT)
    assert hosts[0]["services"][0]["name"] == "http"
    assert hosts[0]["os"] == "Microsoft Windows 2003"


def test_no_os_evidence_keeps_first_service_ostype_fallback():
    hosts = _host_dtos(NO_OS_SERVICE_OSTYPE_REPORT)
    assert hosts[0]["os"] == "Linux"


def test_no_os_evidence_and_no_ostype_stays_unknown():
    hosts = _host_dtos(NO_OS_NO_OSTYPE_REPORT)
    assert hosts[0]["os"] == "unknown"


def test_host_without_os_and_ports_stays_unknown():
    hosts = _host_dtos(EMPTY_HOST_REPORT)
    assert hosts[0]["services"] == []
    assert hosts[0]["os"] == "unknown"
