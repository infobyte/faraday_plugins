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

