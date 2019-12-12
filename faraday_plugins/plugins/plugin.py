"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import os
import re
import uuid
import logging
import simplejson as json
from datetime import datetime


logger = logging.getLogger("faraday").getChild(__name__)


class PluginBase:
    # TODO: Add class generic identifier
    class_signature = "PluginBase"

    def __init__(self):
        # Must be unique. Check that there is not
        # an existant plugin with the same id.
        # TODO: Make script that list current ids.
        self.id = None
        self._rid = id(self)
        self.version = None
        self.name = None
        self.description = ""
        self._command_regex = None
        self._output_file_path = None
        self.framework_version = None
        self._completition = {}
        self._new_elems = []
        self._settings = {}
        self.command_id = None
        self.cache = {}
        self._hosts_cache = {}
        self.start_date = datetime.now()
        self.logger = logger.getChild(self.__class__.__name__)
        self.open_options = {"mode": "r", "encoding": "utf-8"}
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

    def get_from_cache(self, cache_id):
        return self.cache.get(cache_id, None)

    def save_host_cache(self, obj):
        cache_id = f"ip:{obj['ip']}_os:{obj['os']}"
        if cache_id not in self._hosts_cache:
            obj_uuid = self.save_cache(obj)
            self.vulns_data["hosts"].append(obj)
            self._hosts_cache[cache_id] = obj_uuid
        else:
            obj_uuid = self._hosts_cache[cache_id]
        return obj_uuid

    def save_cache(self, obj):
        obj_uuid = uuid.uuid1()
        self.cache[obj_uuid] = obj
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

    def get_ws(self): # TODO Borrar
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
        This method can be overriden in the plugin implementation
        if a different kind of check is needed
        """
        return (self._command_regex is not None and
                self._command_regex.match(current_input.strip()) is not None)

    def getCompletitionSuggestionsList(self, current_input):
        """
        This method can be overriden in the plugin implementation
        if a different kind of check is needed
        """
        words = current_input.split(" ")
        cword = words[len(words) - 1]
        options = {}
        for k, v in self._completition.items():
            if re.search(str("^" + cword), k, flags=re.IGNORECASE):
                options[k] = v
        return options

    def processOutput(self, term_output):
        output = term_output
        if self.has_custom_output() and os.path.isfile(self.get_custom_file_path()):
            self._parse_filename(self.get_custom_file_path())
        else:
            self.parseOutputString(output)

    def _parse_filename(self, filename):
        with open(filename, **self.open_options) as output:
            self.parseOutputString(output.read())

    def processReport(self, filepath, user="faraday"):
        if os.path.isfile(filepath):
            self._parse_filename(filepath)
            self.vulns_data["command"]["params"] = filepath
            self.vulns_data["command"]["user"] = user
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

    def createAndAddHost(self, name, os="unknown", hostnames=None, mac=None, scan_template="", site_name="",
                         site_importance="", risk_score="", fingerprints="", fingerprints_software=""):

        if not hostnames:
            hostnames = []
        if os is None:
            os = "unknown"
        host = {"ip": name, "os": os, "hostnames": hostnames, "description": "",  "mac": mac,
                "credentials": [], "services": [], "vulnerabilities": [], "scan_template": scan_template,
                "site_name": site_name, "site_importance": site_importance, "risk_score": risk_score,
                "fingerprints": fingerprints, "fingerprints_software": fingerprints_software
                }
        host_id = self.save_host_cache(host)
        return host_id

    # @deprecation.deprecated(deprecated_in="3.0", removed_in="3.5",
    #                         current_version=VERSION,
    #                         details="Interface object removed. Use host or service instead")
    def createAndAddInterface(
            self, host_id, name="", mac="00:00:00:00:00:00",
            ipv4_address="0.0.0.0", ipv4_mask="0.0.0.0", ipv4_gateway="0.0.0.0",
            ipv4_dns=None, ipv6_address="0000:0000:0000:0000:0000:0000:0000:0000",
            ipv6_prefix="00",
            ipv6_gateway="0000:0000:0000:0000:0000:0000:0000:0000", ipv6_dns=None,
            network_segment="", hostname_resolution=None):
        if ipv4_dns is None:
            ipv4_dns = []
        if ipv6_dns is None:
            ipv6_dns = []
        if hostname_resolution is None:
            hostname_resolution = []
        if not isinstance(hostname_resolution, list):
            self.logger.warning("hostname_resolution parameter must be a list and is (%s)", type(hostname_resolution))
            hostname_resolution = [hostname_resolution]
        # We don't use interface anymore, so return a host id to maintain
        # backwards compatibility
        # Little hack because we dont want change all the plugins for add hostnames in Host object.
        # SHRUG
        host = self.get_from_cache(host_id)
        for hostname in hostname_resolution:
            if hostname not in host["hostnames"]:
                host["hostnames"].append(hostname)
        host["mac"] = mac
        return host_id

    # @deprecation.deprecated(deprecated_in="3.0", removed_in="3.5",
    #                         current_version=VERSION,
    #                         details="Interface object removed. Use host or service instead. Service will be attached
    # to Host!")
    def createAndAddServiceToInterface(self, host_id, interface_id, name,
                                       protocol="tcp?", ports=None,
                                       status="open", version="unknown",
                                       description=""):
        return self.createAndAddServiceToHost(host_id, name, protocol, ports, status, version, description)

    def createAndAddServiceToHost(self, host_id, name,
                                       protocol="tcp?", ports=None,
                                       status="open", version="unknown",
                                       description=""):
        if ports:
            if isinstance(ports, list):
                ports = int(ports[0])
            elif isinstance(ports, str):
                ports = int(ports)

        if status not in ("open", "closed", "filtered"):
            self.logger.warning('Unknown service status %s. Using "open" instead', status)
            status = 'open'
        service = {"name": name, "protocol": protocol, "port": ports, "status": status,
                   "version": version, "description": description, "credentials": [], "vulnerabilities": []}
        host = self.get_from_cache(host_id)
        host["services"].append(service)
        service_id = self.save_cache(service)
        return service_id

    def createAndAddVulnToHost(self, host_id, name, desc="", ref=None,
                               severity="", resolution="", vulnerable_since="", scan_id="", pci="", data="",
                               external_id=None):
        if ref is None:
            ref = []
        vulnerability = {"name": name, " desc": desc, "severity": self.normalize_severity(severity), "refs": ref,
                         "external_id": external_id, "type": "Vulnerability", "resolution": resolution,
                         "vulnerable_since": vulnerable_since, "scan_id": scan_id, "pci": pci, "data": data}
        host = self.get_from_cache(host_id)

        host["vulnerabilities"].append(vulnerability)
        vulnerability_id = len(host["vulnerabilities"]) - 1
        return vulnerability_id

    # @deprecation.deprecated(deprecated_in="3.0", removed_in="3.5",
    #                         current_version=VERSION,
    #                         details="Interface object removed. Use host or service instead. Vuln will be added
    # to Host")
    def createAndAddVulnToInterface(self, host_id, interface_id, name,
                                    desc="", ref=None, severity="",
                                    resolution="", data=""):
        return self.createAndAddVulnToHost(host_id, name, desc=desc, ref=ref, severity=severity, resolution=resolution,
                                           data=data)

    def createAndAddVulnToService(self, host_id, service_id, name, desc="",
                                  ref=None, severity="", resolution="", risk="", data="", external_id=None):
        if ref is None:
            ref = []
        vulnerability = {"name": name, "desc": desc, "severity": self.normalize_severity(severity), "refs": ref,
                         "external_id": external_id, "type": "Vulnerability", "resolution": resolution, "riskB": risk,
                         "data": data}
        service = self.get_from_cache(service_id)
        service["vulnerabilities"].append(vulnerability)
        vulnerability_id = self.save_cache(vulnerability)
        return vulnerability_id

    def createAndAddVulnWebToService(self, host_id, service_id, name, desc="",
                                     ref=None, severity="", resolution="",
                                     website="", path="", request="",
                                     response="", method="", pname="",
                                     params="", query="", category="", data="", external_id=None):
        if params is None:
            params = ""
        if response is None:
            response = ""
        if method is None:
            method = ""
        if pname is None:
            pname = ""
        if params is None:
            params = ""
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
        if ref is None:
            ref = []
        vulnerability = {"name": name, "desc": desc, "severity": self.normalize_severity(severity), "refs": ref,
                         "external_id": external_id, "type": "VulnerabilityWeb", "resolution": resolution,
                         "data": data, "website": website, "path": path, "request": request, "response": response,
                         "method": method, "pname": pname, "params": params, "query": query, "category": category}
        service = self.get_from_cache(service_id)
        service["vulnerabilities"].append(vulnerability)
        vulnerability_id = self.save_cache(vulnerability)
        return vulnerability_id


    def createAndAddNoteToHost(self, host_id, name, text):
        return None

    def createAndAddNoteToInterface(self, host_id, interface_id, name, text):
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

    def log(self, msg, level='INFO'):# TODO borrar
        pass
        #self.__addPendingAction(Modelactions.LOG, msg, level)

    def devlog(self, msg): # TODO borrar
        pass
        #self.__addPendingAction(Modelactions.DEVLOG, msg)

    def get_data(self):
        self.vulns_data["command"]["tool"] = self.id
        self.vulns_data["command"]["command"] = self.id
        self.vulns_data["command"]["duration"] = (datetime.now() - self.start_date).microseconds
        return self.vulns_data

    def get_json(self):
        self.logger.debug("Generate Json")
        return json.dumps(self.get_data())

# TODO Borrar
class PluginTerminalOutput(PluginBase):
    def __init__(self):
        super().__init__()

    def processOutput(self, term_output):
        try:
            self.parseOutputString(term_output)
        except Exception as e:
            self.logger.error(e)


# TODO Borrar
class PluginCustomOutput(PluginBase):
    def __init__(self):
        super().__init__()

    def processOutput(self, term_output):
        # we discard the term_output since it's not necessary
        # for this type of plugins
        self.processReport(self._output_file_path)


class PluginByExtension(PluginBase):
    def __init__(self):
        super().__init__()
        self.extension = []

    def report_belongs_to(self, extension="", **kwargs):
        match = False
        if type(self.extension) == str:
            match = (self.extension == extension)
        elif type(self.extension) == list:
            match = (extension in self.extension)
        self.logger.debug("Extension Match: [%s =/in %s] -> %s", extension, self.extension, match)
        return match


class PluginXMLFormat(PluginByExtension):

    def __init__(self):
        super().__init__()
        self.identifier_tag = []
        self.extension = ".xml"
        self.open_options = {"mode": "rb"}

    def report_belongs_to(self, main_tag="", **kwargs):
        match = False
        if super().report_belongs_to(**kwargs):
            if type(self.identifier_tag) == str:
                match = (main_tag == self.identifier_tag)
            elif type(self.identifier_tag) == list:
                match = (main_tag in self.identifier_tag)
            self.logger.debug("Tag Match: [%s =/in %s] -> %s", main_tag, self.identifier_tag, match)
        return match


class PluginJsonFormat(PluginByExtension):

    def __init__(self):
        super().__init__()
        self.json_keys = set()
        self.extension = ".json"

    def report_belongs_to(self, file_json_keys=None, **kwargs):
        match = False
        if super().report_belongs_to(**kwargs):
            if file_json_keys is None:
                file_json_keys = {}
            match = self.json_keys.issubset(file_json_keys)
            self.logger.debug("Json Keys Match: [%s =/in %s] -> %s", file_json_keys, self.json_keys, match)
        return match
# I'm Py3