"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
# Standard library imports
import hashlib
import logging
import os
import re
import shutil
import tempfile
import uuid
import zipfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import socket
from typing import List

# Related third party imports
import pytz
import simplejson as json

# Local application imports
from faraday_plugins.plugins.plugins_utils import its_cve, its_cwe

logger = logging.getLogger("faraday").getChild(__name__)

VALID_SERVICE_STATUS = ("open", "closed", "filtered")
VULN_SKIP_FIELDS_TO_HASH = ['run_date']


class PluginBase:
    # TODO: Add class generic identifier
    class_signature = "PluginBase"

    def __init__(self, *args, **kwargs):
        # Must be unique. Check that there is not
        # an existent plugin with the same id.
        # TODO: Make script that list current ids.
        self.ignore_info = kwargs.get("ignore_info", False)
        self.hostname_resolution = kwargs.get("hostname_resolution", True)
        self.vuln_tag = kwargs.get("vuln_tag", None)
        self.host_tag = kwargs.get("host_tag", None)
        self.service_tag = kwargs.get("service_tag", None)
        self.default_vuln_tag = None
        self.id = None
        self.auto_load = True
        self._rid = id(self)
        self.version = None
        self.name = None
        self.description = ""
        self._command_regex = None
        self.command = None
        self._output_file_path = None
        self._use_temp_file = False
        self._delete_temp_file = False
        self._temp_file_extension = "tmp"
        self._current_path = None
        self.framework_version = None
        self._completition = {}
        self._new_elems = []
        self._settings = {}
        self.command_id = None
        self._cache = {}
        self._hosts_cache = {}
        self._service_cache = {}
        self._vulns_cache = {}
        self.start_date = datetime.utcnow()
        self.logger = logger.getChild(self.__class__.__name__)
        self.open_options = {"mode": "r", "encoding": "utf-8"}
        self.plugin_version = "0.0"
        self.vulns_data = {"hosts": [], "command": {"tool": "",
                                                    "command": "",
                                                    "params": "",
                                                    "user": "",
                                                    "hostname": "",
                                                    "start_date": self.start_date.isoformat(),
                                                    "duration": 0,
                                                    "import_source": "report"}}

    def __str__(self):
        return f"Plugin: {self.id}"

    def _get_temp_file(self, extension="tmp"):
        temp_dir = tempfile.gettempdir()
        temp_filename = f"{self.id}_{next(tempfile._get_candidate_names())}.{extension}"
        temp_file_path = os.path.join(temp_dir, temp_filename)
        return temp_file_path

    def resolve_hostname(self, hostname):
        if not self.hostname_resolution:
            return hostname
        if not hostname:
            self.logger.error(f"Hostname provided is None or Empty {hostname}, using 0.0.0.0 as ip")
            return "0.0.0.0"
        try:
            socket.inet_aton(hostname)  # is already an ip
            return hostname
        except OSError:
            pass
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception as e:
            return hostname
        else:
            return ip_address

    @staticmethod
    def get_utctimestamp(date):
        if date is not None:
            try:
                utc_date = date.astimezone(pytz.UTC)
                return utc_date.timestamp()
            except Exception as e:
                logger.error(f"Error generating timestamp: {e}")
                return None
        else:
            return date

    @staticmethod
    def normalize_severity(severity):
        if severity is not None:
            severity = str(severity).lower()
        else:
            severity = ""

        def align_string_based_vulns(severity):
            severities = ['info', 'low', 'med', 'high', 'critical']
            for sev in severities:
                if severity[0:3] in sev:
                    return sev
            return severity

        severity = align_string_based_vulns(severity)
        # Transform numeric severity into desc severity
        numeric_severities = {"0": "info",
                              "1": "low",
                              "2": "med",
                              "3": "high",
                              "4": "critical"}
        if severity not in numeric_severities.values():
            severity = numeric_severities.get(severity, 'unclassified')
        return severity

    # Caches
    def get_from_cache(self, cache_id):
        return self._cache.get(cache_id, None)

    def save_host_cache(self, host):
        cache_id = self.get_host_cache_id(host)
        if cache_id not in self._hosts_cache:
            obj_uuid = self.save_cache(host)
            self.vulns_data["hosts"].append(host)
            self._hosts_cache[cache_id] = obj_uuid
        else:
            obj_uuid = self._hosts_cache[cache_id]
            if host['hostnames']:
                chached_host = self.get_from_cache(obj_uuid)
                chached_host['hostnames'] = list(set(chached_host['hostnames'] + host['hostnames']))
        return obj_uuid

    def save_service_cache(self, host_id, service):
        cache_id = self.get_host_service_cache_id(host_id, service)
        if cache_id not in self._service_cache:
            obj_uuid = self.save_cache(service)
            host = self.get_from_cache(host_id)
            host["services"].append(service)
            self._service_cache[cache_id] = obj_uuid
        else:
            obj_uuid = self._service_cache[cache_id]
        return obj_uuid

    def save_service_vuln_cache(self, host_id, service_id, vuln):
        if self.ignore_info and vuln['severity'] == 'info':
            return None
        else:
            cache_id = self.get_service_vuln_cache_id(host_id, service_id, vuln)
            if cache_id not in self._vulns_cache:
                obj_uuid = self.save_cache(vuln)
                service = self.get_from_cache(service_id)
                service["vulnerabilities"].append(vuln)
                self._vulns_cache[cache_id] = obj_uuid
            else:
                obj_uuid = self._vulns_cache[cache_id]
            return obj_uuid

    def save_host_vuln_cache(self, host_id, vuln):
        if self.ignore_info and vuln['severity'] == 'info':
            return None
        else:
            cache_id = self.get_host_vuln_cache_id(host_id, vuln)
            if cache_id not in self._vulns_cache:
                obj_uuid = self.save_cache(vuln)
                host = self.get_from_cache(host_id)
                host["vulnerabilities"].append(vuln)
                self._vulns_cache[cache_id] = obj_uuid
            else:
                obj_uuid = self._vulns_cache[cache_id]
            return obj_uuid

    @staticmethod
    def _get_dict_hash(d, keys):
        return hash(frozenset(map(lambda x: (x, d.get(x, None)), keys)))

    @classmethod
    def get_host_cache_id(cls, host):
        cache_id = cls._get_dict_hash(host, ['ip'])
        return cache_id

    @classmethod
    def get_host_service_cache_id(cls, host_id, service):
        service_copy = service.copy()
        service_copy.update({"host_cache_id": host_id})
        cache_id = cls._get_dict_hash(service_copy, ['host_cache_id', 'protocol', 'port'])
        return cache_id

    @classmethod
    def get_service_vuln_cache_id(cls, host_id, service_id, vuln):
        vuln_copy = vuln.copy()
        vuln_copy.update({"host_cache_id": host_id, "service_cache_id": service_id})
        cache_id = cls._get_dict_hash(vuln_copy,
                                      ['host_cache_id', 'service_cache_id', 'name', 'desc', 'website', 'path', 'pname',
                                       'method'])
        return cache_id

    @classmethod
    def get_host_vuln_cache_id(cls, host_id, vuln):
        vuln_copy = vuln.copy()
        vuln_copy.update({"host_cache_id": host_id})
        cache_id = cls._get_dict_hash(vuln_copy,
                                      ['host_cache_id', 'name', 'desc', 'website', 'path', 'pname', 'method'])
        return cache_id

    def save_cache(self, obj):
        obj_uuid = uuid.uuid1()
        self._cache[obj_uuid] = obj
        return obj_uuid

    def report_belongs_to(self, **kwargs):
        return False

    def has_custom_output(self):
        return bool(self._output_file_path)

    def get_custom_file_path(self):
        return self._output_file_path

    def set_actions_queue(self, _pending_actions):
        """
            We use plugin controller queue to add actions created by plugins.
            Plugin controller will consume this actions.

        :param controller: plugin controller
        :return: None
        """
        self._pending_actions = _pending_actions

    def setCommandID(self, command_id):
        self.command_id = command_id

    def getSettings(self):
        for param, (param_type, value) in self._settings.items():
            yield param, value

    def get_ws(self):  # TODO Borrar
        return ""

    def getSetting(self, name):
        setting_type, value = self._settings[name]
        return value

    def addSetting(self, param, param_type, value):
        self._settings[param] = param_type, value

    def updateSettings(self, new_settings):
        for name, value in new_settings.items():
            if name in self._settings:
                setting_type, curr_value = self._settings[name]
                self._settings[name] = setting_type, setting_type(value)

    def canParseCommandString(self, current_input):
        """
        This method can be overridden in the plugin implementation
        if a different kind of check is needed
        """
        if (self._command_regex is not None and
                self._command_regex.match(current_input.strip()) is not None):
            self.command = self.get_command(current_input)
            return True

    def get_command(self, current_input: str) -> str:
        command = self._command_regex.findall(current_input)[0]
        if isinstance(command, tuple):
            return "".join(command).strip()

        return command.strip()

    def processCommandString(self, username, current_path, command_string):
        """
        With this method a plugin can add additional arguments to the
        command that it's going to be executed.
        """
        self._current_path = current_path
        if command_string.startswith(("sudo", "python", "python3")):
            params = " ".join(command_string.split()[2:])
        else:
            params = " ".join(command_string.split()[1:])
        self.vulns_data["command"]["params"] = params if not self.ignore_info else f"{params} (Info ignored)"
        self.vulns_data["command"]["user"] = username
        self.vulns_data["command"]["import_source"] = "shell"
        if self._use_temp_file:
            self._delete_temp_file = True
            self._output_file_path = self._get_temp_file(extension=self._temp_file_extension)
        return None

    def getCompletitionSuggestionsList(self, current_input):
        """
        This method can be overridden in the plugin implementation
        if a different kind of check is needed
        """
        words = current_input.split(" ")
        cword = words[len(words) - 1]
        options = {}
        for k, v in self._completition.items():
            if re.search(str("^" + cword), k, flags=re.IGNORECASE):
                options[k] = v
        return options

    def processOutput(self, command_output):
        if self.has_custom_output():
            self._parse_filename(Path(self.get_custom_file_path()))
        else:
            self.parseOutputString(command_output)

    def _parse_filename(self, filename: Path):
        with filename.open(**self.open_options) as output:
            self.parseOutputString(output.read())
        if self._delete_temp_file:
            try:
                if filename.is_file():
                    os.remove(filename)
                elif filename.is_dir():
                    shutil.rmtree(filename)
            except Exception as e:
                self.logger.error(f"Error on delete file: ({filename}) [{e}]")

    def processReport(self, filepath: Path, user="faraday"):
        if isinstance(filepath, str):  # TODO workaround for compatibility, remove in the future
            filepath = Path(filepath)
        if filepath.is_file():
            self.vulns_data["command"]["params"] = filepath.name if not self.ignore_info else f"{filepath.name} (Info ignored)"
            self.vulns_data["command"]["user"] = user
            self.vulns_data["command"]["import_source"] = "report"
            self._parse_filename(filepath)
        else:
            raise FileNotFoundError(filepath)

    def parseOutputString(self, output):
        """
        This method must be implemented.
        This method will be called when the command finished executing and
        the complete output will be received to work with it
        Using the output the plugin can create and add hosts, interfaces,
        services, etc.
        """
        raise NotImplementedError('This method must be implemented.')

    def createAndAddHost(self, name, os="unknown", hostnames=None, mac=None, description="", tags=None):

        if not hostnames:
            hostnames = []
        if not isinstance(hostnames, list):
            hostnames = [hostnames]
        # Some plugins sends a list with None, we filter empty and None values.
        hostnames = [hostname for hostname in hostnames if hostname]
        if os is None:
            os = "unknown"
        if tags is None:
            tags = []
        if isinstance(tags, str):
            tags = [tags]
        if self.host_tag:
            if isinstance(self.host_tag, list):
                tags += self.host_tag
            else:
                tags.append(self.host_tag)
        host = {"ip": name, "os": os, "hostnames": hostnames, "description": description, "mac": mac,
                "credentials": [], "services": [], "vulnerabilities": [], "tags": tags}
        host_id = self.save_host_cache(host)
        return host_id

    def createAndAddServiceToHost(self, host_id, name,
                                  protocol="tcp", ports=None,
                                  status="open", version="",
                                  description="", tags=None):
        if ports:
            if isinstance(ports, list):
                ports = int(ports[0])
            elif isinstance(ports, str):
                ports = int(ports)
        if not protocol:
            protocol = "tcp"
        if status not in VALID_SERVICE_STATUS:
            status = 'open'
        if tags is None:
            tags = []
        if isinstance(tags, str):
            tags = [tags]
        if self.service_tag:
            if isinstance(self.service_tag, list):
                tags += self.service_tag
            else:
                tags.append(self.service_tag)
        service = {"name": name, "protocol": protocol, "port": ports, "status": status,
                   "version": version, "description": description, "credentials": [], "vulnerabilities": [],
                   "tags": tags}

        service_id = self.save_service_cache(host_id, service)

        return service_id

    @staticmethod
    def modify_refs_struct(ref: List[str]) -> List[dict]:
        """
        Change reference struct from list of strings to a list of dicts with the form of {name, type}
        """
        if not ref:
            return []
        refs = []
        for r in ref:
            if isinstance(r, dict):
                refs.append(r)
            else:
                if r.strip():
                    refs.append({'name': r.strip(), 'type': 'other'})
        return refs

    def createAndAddVulnToHost(self, host_id, name, desc="", ref=None,
                               severity="", resolution="", data="", external_id=None, run_date=None,
                               impact=None, custom_fields=None, status="", policyviolations=None,
                               easeofresolution=None, confirmed=False, tags=None, cve=None, cwe=None, cvss2=None,
                               cvss3=None):

        ref = self.modify_refs_struct(ref)
        if status == "":
            status = "open"
        if impact is None:
            impact = {}
        if policyviolations is None:
            policyviolations = []
        if custom_fields is None:
            custom_fields = {}
        if tags is None:
            tags = []
        if isinstance(tags, str):
            tags = [tags]
        if self.vuln_tag:
            if isinstance(self.vuln_tag, list):
                tags += self.vuln_tag
            else:
                tags.append(self.vuln_tag)
        if self.default_vuln_tag:
            if isinstance(self.default_vuln_tag, list):
                tags += self.default_vuln_tag
            else:
                tags.append(self.default_vuln_tag)
        if cve is None:
            cve = []
        elif type(cve) is str:
            cve = [cve]
        cve = its_cve(cve)
        if cwe is None:
            cwe = []
        elif type(cwe) is str:
            cwe = [cwe]
        cwe = its_cwe(cwe)
        if cvss2 is None:
            cvss2 = {}
        if cvss3 is None:
            cvss3 = {}
        vulnerability = {"name": name, "desc": desc, "severity": self.normalize_severity(severity), "refs": ref,
                         "external_id": external_id, "type": "Vulnerability", "resolution": resolution, "data": data,
                         "custom_fields": custom_fields, "status": status, "impact": impact,
                         "policyviolations": policyviolations, "cve":  cve, "cvss3": cvss3, "cvss2": cvss2,
                         "confirmed": confirmed, "easeofresolution": easeofresolution, "tags": tags, "cwe": cwe
                         }
        if run_date:
            vulnerability["run_date"] = self.get_utctimestamp(run_date)
        vulnerability_id = self.save_host_vuln_cache(host_id, vulnerability)
        return vulnerability_id

    def createAndAddVulnToService(self, host_id, service_id, name, desc="",
                                  ref=None, severity="", resolution="", data="", external_id=None, run_date=None,
                                  custom_fields=None, policyviolations=None, impact=None, status="",
                                  confirmed=False, easeofresolution=None, tags=None, cve=None, cwe=None, cvss2=None,
                                  cvss3=None):
        ref = self.modify_refs_struct(ref)
        if status == "":
            status = "open"
        if impact is None:
            impact = {}
        if policyviolations is None:
            policyviolations = []
        if custom_fields is None:
            custom_fields = {}
        if tags is None:
            tags = []
        if isinstance(tags, str):
            tags = [tags]
        if self.vuln_tag:
            if isinstance(self.vuln_tag, list):
                tags += self.vuln_tag
            else:
                tags.append(self.vuln_tag)
        if self.default_vuln_tag:
            if isinstance(self.default_vuln_tag, list):
                tags += self.default_vuln_tag
            else:
                tags.append(self.default_vuln_tag)
        if cve is None:
            cve = []
        elif type(cve) is str:
            cve = [cve]
        cve = its_cve(cve)
        if cwe is None:
            cwe = []
        elif type(cwe) is str:
            cwe = [cwe]
        cwe = its_cwe(cwe)
        if cvss2 is None:
            cvss2 = {}
        if cvss3 is None:
            cvss3 = {}
        vulnerability = {"name": name, "desc": desc, "severity": self.normalize_severity(severity), "refs": ref,
                         "external_id": external_id, "type": "Vulnerability", "resolution": resolution, "data": data,
                         "custom_fields": custom_fields, "status": status, "impact": impact,
                         "policyviolations": policyviolations, "cve": cve, "cvss3": cvss3, "cvss2": cvss2,
                         "easeofresolution": easeofresolution, "confirmed": confirmed, "tags": tags, "cwe": cwe
                         }
        if run_date:
            vulnerability["run_date"] = self.get_utctimestamp(run_date)
        vulnerability_id = self.save_service_vuln_cache(host_id, service_id, vulnerability)
        return vulnerability_id

    def createAndAddVulnWebToService(self, host_id, service_id, name, desc="",
                                     ref=None, severity="", resolution="",
                                     website="", path="", request="",
                                     response="", method="", pname="",
                                     params="", query="", category="", data="", external_id=None,
                                     confirmed=False, status="", easeofresolution=None, impact=None,
                                     policyviolations=None, status_code=None, custom_fields=None, run_date=None,
                                     tags=None, cve=None, cvss2=None, cvss3=None, cwe=None):
        if params is None:
            params = ""
        if method is None:
            method = ""
        if pname is None:
            pname = ""
        if query is None:
            query = ""
        if website is None:
            website = ""
        if path is None:
            path = ""
        if request is None:
            request = ""
        if response is None:
            response = ""
        ref = self.modify_refs_struct(ref)
        if status == "":
            status = "open"
        if impact is None:
            impact = {}
        if policyviolations is None:
            policyviolations = []
        if custom_fields is None:
            custom_fields = {}
        if tags is None:
            tags = []
        if isinstance(tags, str):
            tags = [tags]
        if self.vuln_tag:
            if isinstance(self.vuln_tag, list):
                tags += self.vuln_tag
            else:
                tags.append(self.vuln_tag)
        if self.default_vuln_tag:
            if isinstance(self.default_vuln_tag, list):
                tags += self.default_vuln_tag
            else:
                tags.append(self.default_vuln_tag)
        if cve is None:
            cve = []
        elif type(cve) is str:
            cve = [cve]
        cve = its_cve(cve)
        if cwe is None:
            cwe = []
        elif type(cwe) is str:
            cwe = [cwe]
        cwe = its_cwe(cwe)
        if cvss2 is None:
            cvss2 = {}
        if cvss3 is None:
            cvss3 = {}
        vulnerability = {"name": name, "desc": desc, "severity": self.normalize_severity(severity), "refs": ref,
                         "external_id": external_id, "type": "VulnerabilityWeb", "resolution": resolution,
                         "data": data, "website": website, "path": path, "request": request, "response": response,
                         "method": method, "pname": pname, "params": params, "query": query, "category": category,
                         "confirmed": confirmed, "status": status, "easeofresolution": easeofresolution,
                         "impact": impact, "policyviolations": policyviolations, "cve": cve,  "cvss3": cvss3,
                         "cvss2": cvss2, "status_code": status_code, "custom_fields": custom_fields, "tags": tags,
                         "cwe": cwe}
        if run_date:
            vulnerability["run_date"] = self.get_utctimestamp(run_date)
        vulnerability_id = self.save_service_vuln_cache(host_id, service_id, vulnerability)
        return vulnerability_id

    def createAndAddNoteToHost(self, host_id, name, text):
        return None

    def createAndAddNoteToService(self, host_id, service_id, name, text):
        return None

    def createAndAddNoteToNote(self, host_id, service_id, note_id, name, text):
        return None

    def createAndAddCredToService(self, host_id, service_id, username, password):
        credential = {"name": "credential", "username": username, "password": password}
        service = self.get_from_cache(service_id)
        service["credentials"].append(credential)
        credential_id = self.save_cache(credential)
        return credential_id

    def get_data(self):
        self.vulns_data["command"]["tool"] = self.id
        self.vulns_data["command"]["command"] = self.command if self.command else self.id
        self.vulns_data["command"]["duration"] = (datetime.utcnow() - self.start_date).microseconds
        return self.vulns_data

    def get_json(self):
        self.logger.debug("Generate Json")
        return json.dumps(self.get_data())

    def get_summary(self):
        plugin_json = self.get_data()
        summary = {'hosts': len(plugin_json['hosts']), 'services': 0,
                   'hosts_vulns': sum(list(map(lambda x: len(x['vulnerabilities']), plugin_json['hosts']))),
                   'services_vulns': 0, 'severity_vulns': defaultdict(int),
                   'vuln_hashes': []
                   }
        hosts_with_services = filter(lambda x: len(x['services']) > 0, plugin_json['hosts'])
        host_services = list(map(lambda x: x['services'], hosts_with_services))
        summary['services'] = sum(map(lambda x: len(x), host_services))
        services_vulns = 0
        for host in plugin_json['hosts']:
            for vuln in host['vulnerabilities']:
                summary['severity_vulns'][vuln['severity']] += 1
        for services in host_services:
            for service in services:
                services_vulns += len(service['vulnerabilities'])
                for vuln in service['vulnerabilities']:
                    summary['severity_vulns'][vuln['severity']] += 1
        summary['services_vulns'] = services_vulns
        for obj_uuid in self._vulns_cache.values():
            vuln = self.get_from_cache(obj_uuid)
            vuln_copy = vuln.copy()
            for field in VULN_SKIP_FIELDS_TO_HASH:
                vuln_copy.pop(field, None)
            dict_hash = hashlib.sha1(json.dumps(vuln_copy).encode()).hexdigest() # nosec
            summary['vuln_hashes'].append(dict_hash)
        return summary


# TODO Borrar
class PluginTerminalOutput(PluginBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def processOutput(self, term_output):
        try:
            self.parseOutputString(term_output)
        except Exception as e:
            self.logger.error(e)


# TODO Borrar
class PluginCustomOutput(PluginBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def processOutput(self, term_output):
        # we discard the term_output since it's not necessary
        # for this type of plugins
        self.processReport(Path(self._output_file_path))


class PluginByExtension(PluginBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.extension = []

    def report_belongs_to(self, extension="", **kwargs):
        match = False
        if isinstance(self.extension, str):
            match = (self.extension == extension)
        elif isinstance(self.extension, list):
            match = (extension in self.extension)
        self.logger.debug(f"Extension Match: [{extension} =/in {self.extension}] -> {match}")
        return match


class PluginXMLFormat(PluginByExtension):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.identifier_tag = []
        self.identifier_tag_attributes = {}
        self.extension = ".xml"
        self.open_options = {"mode": "rb"}

    def report_belongs_to(self, main_tag="", main_tag_attributes={}, **kwargs):
        match = False
        if super().report_belongs_to(**kwargs):
            if isinstance(self.identifier_tag, str):
                match = (main_tag == self.identifier_tag)
            elif isinstance(self.identifier_tag, list):
                match = (main_tag in self.identifier_tag)
            if self.identifier_tag_attributes:
                match = self.identifier_tag_attributes.issubset(main_tag_attributes)
            self.logger.debug(f"Tag Match: [{main_tag} =/in {self.identifier_tag}] -> {match}")
        return match


class PluginJsonFormat(PluginByExtension):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.json_keys = set()
        self.filter_keys = set()
        self.extension = ".json"

    def report_belongs_to(self, file_json_keys=None, **kwargs):
        match = False
        if super().report_belongs_to(**kwargs):
            if file_json_keys is None:
                file_json_keys = set()
            if self.filter_keys & file_json_keys:
                return match
            if isinstance(self.json_keys, list):
                for jk in self.json_keys:
                    match = jk.issubset(file_json_keys)
                    self.logger.debug(f"Json Keys Match: [{file_json_keys} =/in {jk}] -> {match}")
                    if match:
                        break
            else:
                match = self.json_keys.issubset(file_json_keys)
                self.logger.debug(f"Json Keys Match: [{file_json_keys} =/in {self.json_keys}] -> {match}")
        return match


class PluginMultiLineJsonFormat(PluginByExtension):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.json_keys = set()
        self.extension = ".json"

    def report_belongs_to(self, file_json_keys=None, **kwargs):
        match = False
        report_path = kwargs.get("report_path", "")
        if super().report_belongs_to(**kwargs):
            with open(report_path) as f:
                try:
                    json_lines = list(map(lambda x: json.loads(x), f.readlines()))
                    if len(json_lines) > 0:
                        matched_lines = list(filter(lambda json_line: self.json_keys.issubset(json_line.keys()),
                                                    json_lines))
                        match = len(matched_lines) == len(json_lines)
                        self.logger.debug(f"Json Keys Match: [{json_lines[0].keys()} =/in {self.json_keys}] -> {match}")
                except ValueError:
                    return False
        return match


class PluginCSVFormat(PluginByExtension):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.extension = ".csv"
        self.csv_headers = set()

    def report_belongs_to(self, file_csv_headers=None, **kwargs):
        match = False
        if file_csv_headers is None:
            file_csv_headers = set()
        if super().report_belongs_to(**kwargs):
            if isinstance(self.csv_headers, list):
                match = bool(list(filter(lambda x: x.issubset(file_csv_headers), self.csv_headers)))
            else:
                match = self.csv_headers.issubset(file_csv_headers)
            self.logger.debug(f"CSV Headers Match: [{file_csv_headers} =/in {self.csv_headers}] -> {match}")
        return match


class PluginZipFormat(PluginByExtension):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.extension = ".zip"
        self.files_list = set()

    def _parse_filename(self, filename):
        file = zipfile.ZipFile(filename, "r")
        self.parseOutputString(file)

    def report_belongs_to(self, files_in_zip=None, **kwargs):
        match = False
        if super().report_belongs_to(**kwargs):
            if files_in_zip is None:
                files_in_zip = set()
            match = bool(self.files_list & files_in_zip)
            self.logger.debug(f"Files List Match: [{files_in_zip} =/in {self.files_list}] -> {match}")
        return match
