1.5.3 [Sep 7th, 2021]:
---
 * Adding support for running nuclei through command / faraday-cli 
 * Fix missing references in nuclei

1.5.2 [Aug 9th, 2021]:
---
 * add new structure acunetix 

1.5.1 [Jul 27th, 2021]:
---
 * cwe, capec, references, tags, impact, resolution, easeofresolution
 * add os openvas
 * [FIX] Fix improt of CSV with big fields
 * Fix sslyze json bug with port
 * Only show report name in command data

1.5.0 [Jun 28th, 2021]:
---
 * Add Nipper Plugin
 * add shodan plugin
 * fix acunetix url parser
 * FIX netsparker multi-host
 * Add vuln details for Certificate Mismatch and move unique details to data, now vulns can be grupped
 * ADD more data to plugins arachni and w3af
 * Use run_date in UTC
 * ADD cvss_base, cpe, threat, severity into references

1.4.6 [May 14th, 2021]:
---
 * - add attribute "command" for the pluggins of each command
- adding test in test_command
- change some regex in self._command_regex
 * [FIX] add hostnames if host is already cached
 * Add Naabu plugin
 * Add Sonarqube plugin
 * Add version and change list_plugins style
 * FIX unused import, innecesary list compression and unused variables
 * FIX metasploit report when the web-site-id is null
 * Fix port stats in nmap
 * fixup ssylze
sacar unknown de version=
 * ADD remedy into resolution
 * Support for nuclei 2.3.0
 * ADD cve, cvss3_base_score, cvss3_vector, exploit_available when import nessus and change the structure of external_id to NESSUS-XXX
 * ADD more data like attack, params, uri, method, WASC, CWE and format externail_id

1.4.5 [Apr 15th, 2021]:
---
 * Add Bandit plugin
 * Use background for description and detail for data en Burp plugin.
 * Rewrite Appscan Plugin
 * Parse Nmap vulners script data

1.4.4 [Mar 30th, 2021]:
---
 * Faraday CSV Plugin do not consider ignore_info

1.4.3 [Mar 17th, 2021]:
---
 * Add Ignore information vulnerabilities option

1.4.2 [Mar 10th, 2021]:
---
 * Fix bug with sslyze output file
 * FIX change id sslyze for JSON/XML

1.4.1 [Feb 26th, 2021]:
---
 * ADD microsoft baseline security analyzer plugin
 * ADD nextnet plugin
 * ADD openscap plugin 
 * FIX old versions of Nessus plugins bugs

1.4.0 [Dec 23rd, 2020]:
---
 * Update the fields of the nuclei output used to create a vuln

1.4.0b2 [Dec 15th, 2020]:
---
 * Fix nuclei plugin bug when url is None

1.4.0b1 [Dec 14th, 2020]:
---
 * Add new plugin base class, for multi line json
 * New ncrack plugin 
 * New nuclei plugin
 * New sslyze json plugin
 * New WhatWeb plugin
 * Fix missing ip in some arachni reports
 * Fix change name vuln in Netsparker plugin
 * Fix whois plugin, command whois IP not parse data
 * Change the way we detect json reports when they are lists of dictionaries

1.3.0 [Sep 2nd, 2020]:
---
 * ADD plugin AppSpider
 * Add tests to faraday-plugins cli
 * add a default value to plugin_version
 * Add --output-file parameter to faraday-plugins process command
 * Add plugins prowler
 * Add plugins ssl labs
 * Add support for tenable io
 * delete old deprecated methods
 * Bug fix: Arachni Plugin 'NoneType' object has no attribute 'find'
 * Bug fix: Openvas Plugin - Import xml from OpenVas doesnt work
 * Bug fix: QualysWebApp Plugin, error in get info OPERATING_SYSTEM
 * Fix Hydra plugin to resolve ip address
 * Fix Nessus mod severity HIGH for Low 
 * Bug Fix: Detect plugins AWS Prowler
 * Fix broken xml on nmap plugin
 * Add new rdpscan plugin
 * UPDATE xml report to appscan
 * Update Readme
 * Fix how ZAP genereate vulns

