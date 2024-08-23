1.19.0 [Aug 23rd, 2024]:
---
 * [ADD] Added owasp dependency check. #100
 * [ADD] Added gitleaks plugin. #342
 * [FIX] Nessus plugin crashed when parsing tenableio reports without vulnerabilities, so a check for that was added. #341

1.18.2 [Jul 24th, 2024]:
---
 * [FIX] Added validations for empty lines and multiple fields including lists. #343

1.18.1 [Jul 11th, 2024]:
---
 * [MOD] Naabu reports changed their JSON structure, so new keys were added to detect the new report structure. #339

1.18.0 [May 22th, 2024]:
---
 * [FIX] Fix key error when `packageVulnerabilityDetails` key was not in the file. #331
 * [FIX] Addressed a bug where Burp plugin output would display null data in cases of encountering a malformed XML token from the report. #333
 * [FIX] Previously, CSV files edited in tools like Mac Numbers would transform boolean values to uppercase. This issue has been addressed within the faraday_csv plugin, ensuring accurate comparison. #336

1.17.0 [Mar 12th, 2024]:
---
 * [ADD] Add hotspots logic for sonarqube plugin #321

1.16.0 [Feb 8th, 2024]:
---
 * [ADD] Add Snyk plugin. #314
 * [MOD] Mod AWS Inspector's plugins. #322
 * [ADD] Add faraday_json plugins. #324
 * [ADD] Update prowler plugin to support the latest tool output format. Also rename the oldest plugin to prowler_legacy. #328

1.15.1 [Dec 22th, 2023]:
---
 * [FIX] Filter \x00 in nuclei response. #323

1.15.0 [Dec 12th, 2023]:
---
 * [ADD] Add PopEye's plugin. #303
 * [ADD] Add Ping Castle's plugin. #304
 * [ADD] Add Kubescape's plugin. #320
 * [ADD] Add AWS Inspector's plugins. #322

1.14.0 [Oct 10th, 2023]:
---
 * [ADD] Add Crowdstrike's plugin. #318

1.13.2 [Sep 6th, 2023]:
---
 * [ADD] Extract response and request info in qualyswebapp's plugins. #307
 * [ADD] Create Plugin for windows defender. #315

1.13.0 [Aug 24th, 2023]:
---
 * [FIX] If severity id in an appscan item is greater than 4 set it to 4. #305
 * [FIX] Update Naabu plugin for the latest version, Semgrep create a new service for each vuln, fix Arachni bug in case the report has no vulns. #306
 * [ADD] Add Terrascan and TFSec plugins. #310
 * [FIX] Use cvss_score to calculate severity in nessus plugin. #311

1.12.1 [July 7th, 2023]:
---
 * [FIX] Fix Appscan's pluign. #302

1.12.0 [May 24th, 2023]:
---
 * [ADD] Add Sarif plugin. #299

1.11.0 [Apr 3rd, 2023]:
---
 * [FIX] Change syhunt´s and trivy´s plugins to export cvss vector correctly #292
 * [ADD] Add force flag to process-command to process the output of the command regardless of the exit code. #294
 * [MOD] The accunetix plugin now search for CVSS and cvss #296
 * [ADD] Add semgrep plugin. #297
 * [FIX] Fix inviti's plugin, check remedial procedures before parsing it with b4f. #298

1.10.0 [Jan 31th, 2023]:
---
 * [ADD] Add new acunetix360 plugin #293

1.9.1 [Jan 3rd, 2023]:
---
 * [ADD] Add new CIS plugin

1.9.0 [Dic 15th, 2022]:
---
 * [FIX] Now all plugins check that service protocol is not empty
 * [ADD] New pentera plugin and now json plugins can have filter_key to filter reports with that keys
 * [MOD] Change table format for list-plugins to github

1.8.1 [Nov 28th, 2022]:
---
 * [FIX] Nuclei's plugin check if the cwe is null and add retrocompability for newer versions for wpscan plugin
 * [ADD] Add cvss2/3 and cwe to faraday_csv plugin
 * [Add] Now nexpose_full plugin use severity from reports
 * [FIX] Now plugins check if the ref is empty

1.8.0:
---
 * [Add] Add invicti plugin
 * [Add] Add nessus_sc plugin
 * [FIX] Remove cvss_vector from refs in nexpose_full
 * Add new identifier_tag to nikto plugin
 * [FIX] Now plugins check if ref field is already a dictionary
 * [MOD] Improve grype plugin for dockers images and change report_belong_to method for
json plugins to check if json_keys is a list, in that case iterate the list and try if
any of them create a match.

1.7.0 [Sep 5th, 2022]:
---
 * Add CWE to PluginBase. The plugins that have this implemented are the following:
"Acunetix",
"Acunetix_Json",
"AppSpider",
"Appscan",
"Arachni",
"Burp",
"Checkmarx",
"Metasploit",
"Nessus",
"Netsparker",
"NetsparkerCloud",
"Openvas",
"QualysWebapp",
"W3af",
"Wapiti",
"Zap",
"Zap_Json",
"nuclei",
"nuclei_legacy"
 * Now the nexts pluggins extracts cvss from reports:

- Acunetix
- Acunetix_Json
- Appscan
- Nessus
- Netsparker
- NexposeFull
- Nipper
- Nmap
- Openvas
- QualysWebapp
- Qualysguard
- Retina
- shodan
- whitesource
 * Add arguments for add tags for vulns, services and host.

Add test for tags and ignore_info
 * Add trivy's json plugin
 * Add command support for the wpscan plugin
 * [MOD] Now refs field is a list of dictionary with the format:
    {'name': string, 'type': string},
 * Fix for acunetix_json when host is ip
 * [FIX] - Asset duplicated on same file with multiple entries for Appscan_csv plugin.
 * [FIX] Change import dateutil to from dateutil.parser import parse
for compatibility issues with python 3.10
 * [FIX] Add case for Netsparker plugins, when the url has a number inside a parenthesis.
 * Add *args **kwargs to syhunt plugin
 * fix bug when grype report has no arifact/metadata
 * [MOD] Now prowler plugin returns CAF Epic as policy violation and
remove [check#] from tittle

1.6.8 [Jul 25th, 2022]:
---
 * Add appscan csv
 * Now faraday_csv's plugin uses ignore_info parameter
 * Add syhunt plugin
 * Add cve and data fields to desc for avoid duplications
 * Now nuclei resolve hostname if the field ip is None

1.6.7 [Jun 2nd, 2022]:
---
 * Change hostname_restolution to dont_resolve_hostname for process-report and now test dosent resovle hostname
 * Now QualysWebApp's plugin will diferenciate vulns from differents urlpaths

1.6.6 [May 20th, 2022]:
---
 * Add hostname_resolution parameter within plugins
 * Fix openvas external ID

1.6.5 [Apr 28th, 2022]:
---
 * Now Openvas's plugin set severity to Critical when cvss >= 9.0

1.6.4 [Apr 21th, 2022]:
---
 * Add location as params in burp's plugin
 * Now the faraday_csv custom_fields regex match any no whitespace character.

1.6.3 [Apr 19th, 2022]:
---
 * Add Zap Json plugin.

1.6.2 [Apr 4th, 2022]:
---
 * Now Appscan plugin saves line and highlight of the vulns in desc and data

1.6.1 [Mar 18th, 2022]:
---
 * Add references tu burp plugin
 * Move item.detail from data to desc
 * update open status

1.6.0 [Feb 3rd, 2022]:
---
 * Add packaging to requierments in setup.py
 * Add severity to shodan's plugins using cvss
 * check if cve exist on cve-id field
 * Fix Fortify's plugin
 * Change qualysguard's plugin severity_dict to refer level 2 severities as low

1.5.10 [Jan 13th, 2022]:
---
 * support cve,cwe,cvss and metadata

1.5.9 [Dec 27th, 2021]:
---
 * Add cve in faraday_csv plugin
 * ADD Grype plugin

1.5.8 [Dec 13th, 2021]:
---
 * Add CVE to plugins
- acunetix
- appscan
- burp
- metasploit
- nessus
- netsparker
- nexpose
- nikto
- nipper
- nmap
- openscap
- qualysguard
- retina
- shodan
 * Add support for Sslyze 5.0 resports
 * Fix errors while creating hosts with wrong regex
 * ADD masscan support to nmap plugin
 * Fix bug in openvas plugin

1.5.7 [Nov 19th, 2021]:
---
 * FIX extrainfo of netsparker plugin
 * Add nuclei_legacy plugin

1.5.6 [Nov 10th, 2021]:
---
 * FIX issue with acunetix plugin

 * FIX typo in nikto plugin

1.5.5 [Oct 21st, 2021]:
---
 * Merge PR from github

1.5.4 [Oct 19th, 2021]:
---
 * Update nuclei parser

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
