"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from faraday_plugins.plugins.plugin import PluginBase
import re
import json
import traceback
import os

__author__ = "xtr4nge"
__copyright__ = "Copyright (c) 2016, FruityWiFi"
__credits__ = ["xtr4nge"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "xtr4nge"
__email__ = "@xtr4nge"
__status__ = "Development"

class FruityWiFiPlugin(PluginBase):
    """
    This plugin handles FruityWiFi clients.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "fruitywifi"
        self.name = "FruityWiFi"
        self.plugin_version = "0.0.1"
        self.version = "2.4"
        self.description = "http://www.fruitywifi.com"
        self.options = None
        self._current_output = None
        self.target = None
        
        self._command_regex = re.compile(r'^(fruitywifi)\s+.*?')
        
        self.addSetting("Token", str, "e5dab9a69988dd65e578041416773149ea57a054")
        self.addSetting("Server", str, "http://127.0.0.1:8000")
        self.addSetting("Severity", str, "high")
    
    def getSeverity(self, severity):
        if severity.lower() == "critical" or severity == "4":
            return 4
        elif severity.lower() == "high" or severity == "3":
            return 3
        elif severity.lower() == "med" or severity == "2":
            return 2
        elif severity.lower() == "low" or severity == "1":
            return 1
        elif severity.lower() == "info" or severity == "0":
            return 0
        else:
            return 5
    
    def createHostInterfaceVuln(self, ip_address, macaddress, hostname, desc, vuln_name, severity):
        h_id = self.createAndAddHost(ip_address, hostnames=[hostname])

        self.createAndAddVulnToHost(
            h_id,
            vuln_name,
            desc=desc,
            ref=["http://www.fruitywifi.com/"],
            severity=severity
        )
    
    def parseOutputString(self, output):
        
        try:
            output = json.loads(output)
            
            if len(output) > 0:
                
                if len(output[0]) == 3:
                    
                    severity = self.getSeverity(self.getSetting("Severity"))
                    
                    for item in output:
                        ip_address = item[0]
                        macaddress = item[1]
                        hostname = item[2]
                        vuln_name = "FruityWiFi"
                        severity = severity
            
                        desc = "Client ip: " + ip_address + \
                               " has been connected to FruityWiFi\n"
                        desc += "More information:"
                        desc += "\nname: " + hostname
                        
                        self.createHostInterfaceVuln(ip_address, macaddress, hostname, desc, vuln_name, severity)
            
                elif len(output[0]) == 5:
                    for item in output:
                        ip_address = item[0]
                        macaddress = item[1]
                        hostname = item[2]
                        vuln_name = item[3] 
                        severity = item[4]
            
                        desc = "Client ip: " + ip_address + \
                               " has been connected to FruityWiFi\n"
                        desc += "More information:"
                        desc += "\nname: " + hostname
            
                        self.createHostInterfaceVuln(ip_address, macaddress, hostname, desc, vuln_name, severity)
                        
        except:
            traceback.print_exc()
            
        return True

    def _isIPV4(self, ip):
        if len(ip.split(".")) == 4:
            return True
        else:
            return False

    def processCommandString(self, username, current_path, command_string):
        """
        """        
        super().processCommandString(username, current_path, command_string)
        params = "-t %s -s %s" % (self.getSetting("Token"), self.getSetting("Server"))
        
        return "python " + os.path.dirname(__file__) + "/fruitywifi.py " + params



def createPlugin(ignore_info=False):
    return FruityWiFiPlugin(ignore_info=ignore_info)


