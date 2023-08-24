"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import os
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from faraday_plugins.plugins.plugin import PluginXMLFormat

__author__ = 'Ezequiel Tavella'
__copyright__ = 'Copyright 2016, Faraday Project'
__credits__ = ['Ezequiel Tavella', 'Matías Ariel Ré Medina', 'Conrad Stein K']
__license__ = ''
__version__ = '1.0.2'
__status__ = 'Development'


class ArachniXmlParser:
    def __init__(self, xml_output):

        self.tree = self.parse_xml(xml_output)
        if self.tree:
            self.issues = self.getIssues(self.tree)
            self.plugins = self.getPlugins(self.tree)
            self.system = self.getSystem(self.tree)
        else:
            self.system = None
            self.issues = None
            self.plugins = None

    def parse_xml(self, xml_output):
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError as err:
            return None
        return tree

    def getIssues(self, tree):
        # Get vulnerabilities.
        issues_tree = tree.find('issues')
        for self.issue_node in issues_tree:
            yield Issue(self.issue_node)

    def getPlugins(self, tree):
        # Get info about plugins executed in scan.
        plugins_tree = tree.find('plugins')
        return Plugins(plugins_tree)

    def getSystem(self, tree):
        system_tree = tree.find('system')
        if system_tree is None:
            return System(tree, False)
        else:
            return System(system_tree, True)


class Issue:

    def __init__(self, issue_node):
        self.node = issue_node
        self.name = self.getDesc('name')
        self.severity = self.getDesc('severity')
        self.cwe = self.getDesc('cwe')
        self.remedy_guidance = self.getDesc('remedy_guidance')
        self.description = self.getDesc('description')
        self.var = self.getChildTag('vector', 'affected_input_name')
        self.url = self.getChildTag('vector', 'url')
        self.method = self.getChildTag('vector', 'method')
        self.references = self.getReferences()
        self.parameters = self.getParameters()
        self.request = self.getRequest()
        self.response = self.getResponse()
        self.data = self.getData()

    def getData(self):
        name = self.node.findtext('check/name', '')
        description = self.node.findtext('check/description', '')
        author = self.node.findtext('check/description', '')
        data = ""
        if name:
            data += f'\nname: {name}'
        if description:
            data += f'\ndescription: {description}'
        if author:
            data += f'\nauthor: {author}'

        return data

    def getDesc(self, tag):

        # Get value of tag xml
        description = self.node.find(tag)

        if description is not None and description.text is not None:
            return description.text
        else:
            return 'None'

    def getChildTag(self, main_tag, child_tag):

        # Get value of tag child xml
        main_entity = self.node.find(main_tag)

        if not main_entity:
            return 'None'

        result = main_entity.find(child_tag)

        if result is not None and result.text is not None:
            return result.text
        else:
            return 'None'

    def getReferences(self):
        """
        Returns current issue references on this format
        {'url': 'http://www.site.com', 'name': 'WebSite'}.
        """
        result = []
        references = self.node.find('references')

        if not references:
            return result

        for tag in references.findall('reference'):
            url = tag.get('url')
            result.append(url)

        return result

    def getParameters(self):

        # Get parameters of query
        result = []

        try:
            parameters = self.node.find('vector').find('inputs')
            for param in parameters.findall('input'):
                name = param.get('name')
                result.append(name)
        except:
            parameters = ''

        return ' - '.join(result)

    def getRequest(self):

        # Get data about request.
        try:
            request = self.node.find('page/request')
            raw_data = request.find('raw')
            data = raw_data.text
            if not data:
                data = self.contruct_request(request)
            return data
        except:
            return 'None'

    @staticmethod
    def contruct_request(request):
        data = request.findtext("method", "").upper()
        data += f" {request.findtext('url', '')}"
        for h in request.findall('headers/header'):
            data += f"\n{h.get('name')}: {h.get('value')}"
        if request.findtext('body',""):
            data += f"\n{request.findtext('body','')}"
        return data

    @staticmethod
    def construct_response(request):
        data = ""
        if request.findtext("code", ""):
            data += f'\ncode: {request.findtext("code", "")}'
        if request.findtext("ip_address", ""):
            data += f'\nip_address: {request.findtext("ip_address", "")}'
        if request.findtext("time", ""):
            data += f'\ntime: {request.findtext("time", "")}'
        if request.findtext("return_code", ""):
            data += f'\nreturn_code: {request.findtext("return_code", "")}'
        if request.findtext("return_message", ""):
            data += f'\nreturn_message: {request.findtext("return_message", "")}'
        return data

    def getResponse(self):

        try:
            request = self.node.find('page/response')
            raw_data = request.find('raw_headers')
            data = raw_data.text
            if not data:
                data = self.contruct_request(request)
            data += self.construct_response(request)
            return data
        except:
            return 'None'


class System:

    def __init__(self, node, tag_exists):
        self.node = node
        if not tag_exists:
            self.user_agent = 'Arachni'
            self.url = self.getUrl()
            self.modules = ''
            self.version = self.node.find('version')
            self.start_time = self.node.find('start_datetime')
            self.finish_time = self.node.find('finish_datetime')
        else:
            self.user_agent = None
            self.url = None
            self.audited_elements = None
            self.modules = ''
            self.cookies = None
            self.getOptions()
            self.version = self.getDesc('version')
            self.start_time = self.getDesc('start_datetime')
            self.finish_time = self.getDesc('finish_datetime')
            self.note = self.getNote()

    def getUrl(self):
        sitemap = self.node.find("sitemap/entry")
        #Fix for the case when no vulns in the report
        if not sitemap:
            return self.node.find("options").text.split("url:")[-1].strip(" \n")
        return sitemap.get('url')

    def getOptions(self):

        # Get values of options scan
        try:
            options = self.node.find('options')
        except:
            options = False
        if options:
            options_string = options.text
        else:
            options_string = None

        try:
            self.user_agent = self.node.find('user_agent').text
        except:
            self.user_agent = None

        self.url = self.node.find('url').text
        tags_audited_elements = self.node.find('audited_elements')
        element_text = []
        for element in tags_audited_elements:
            element_text.append(element.text)
        self.audited_elements = element_text
        tag_module = self.node.find('modules')
        module_text = []
        for module in tag_module:
            module_text.append(module.attrib['name'])
        self.modules = module_text
        self.cookies = self.node.find('cookies').text

    def getDesc(self, tag):

        # Return value of tag
        description = self.node.find(tag)

        if description and description.text:
            return description.text
        else:
            return None

    def getNote(self):
        result = ('Scan url:\n {} \nUser Agent:\n {} \nVersion Arachni:\n {} \nStart time:\n {} \nFinish time:\n {}'
                  '\nAudited Elements:\n {} \nModules:\n {} \nCookies:\n {}').format(self.url, self.user_agent,
                                                                                     self.version, self.start_time,
                                                                                     self.finish_time,
                                                                                     self.audited_elements,
                                                                                     self.modules, self.cookies)

        return result


class Plugins:
    """
    Support:
    WAF (Web Application Firewall) Detector (waf_detector)
    Healthmap (healthmap)
    """

    def __init__(self, plugins_node):

        self.plugins_node = plugins_node
        self.healthmap = self.getHealthmap()
        self.waf = self.getWaf()
        try:
            self.ip = plugins_node.find('resolver').find('results') \
                .find('hostname').get('ipaddress')
        except Exception:
            self.ip = None

    @staticmethod
    def get_value(name, node):
        x = node.find(name)
        if x:
            return x.text
        else:
            return ""

    def getHealthmap(self):

        # Get info about healthmap
        healthmap_tree = self.plugins_node.find('healthmap')
        if not healthmap_tree:
            return 'None'

        # Create urls list.
        list_urls = []
        map_results = healthmap_tree.find('results').find('map')

        for url in map_results:

            if url.tag == 'with_issues':
                list_urls.append(f"With Issues: {url.text}")
            else:
                list_urls.append(f"Without Issues: {url.text}")

        try:
            plugin_name = self.get_value('name', healthmap_tree)
            description = self.get_value('description', healthmap_tree)
            results = self.get_value('results', healthmap_tree)
            total = self.get_value('total', results)
            with_issues = self.get_value('with_issues', results)
            without_issues = self.get_value('without_issues', results)
            issue_percentage = self.get_value('issue_percentage', results)

            urls = '\n'.join(list_urls)
            result = (f"Plugin Name: {plugin_name}\nDescription: {description}\nStatistics:\nTotal: {total}"
                      f"\nWith Issues: {with_issues}\nWithout Issues: {without_issues}"
                      f"\nIssues percentage: {issue_percentage}\nResults Map:\n {urls}")
            return result

        except:
            return 'None'

    def getWaf(self):

        # Get info about waf plugin.
        waf_tree = self.plugins_node.find('waf_detector')
        try:
            plugin_name = self.get_value('name', waf_tree)
            description = self.get_value('description', waf_tree)
            results = waf_tree.find('results')
            message = self.get_value('message', results)
            status = self.get_value('status', results)
            result = (f"Plugin Name: {plugin_name}\nDescription: {description}\nResults:"
                      f"\nMessage: {message}\nStatus: {status}")
            return result
        except:
            return 'None'


class ArachniPlugin(PluginXMLFormat):

    # Plugin that parses Arachni's XML report files.

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = ["report", "arachni_report"]
        self.id = 'Arachni'
        self.name = 'Arachni XML Output Plugin'
        self.plugin_version = '1.0.1'
        self.version = '1.3.2'
        self.framework_version = '1.0.0'
        self.options = None
        self._command_regex = re.compile(r'^(arachni|\.\/arachni)\s+.*?')
        self.protocol = None
        self.hostname = None
        self.port = '80'
        self.address = None
        self._use_temp_file = True
        self._temp_file_extension = ["afr", "xml"]

    def report_belongs_to(self, **kwargs):
        if super().report_belongs_to(**kwargs):
            report_path = kwargs.get("report_path", "")
            with open(report_path) as f:
                output = f.read()
            return re.search("/Arachni/arachni/", output) is not None
        return False

    def _parse_filename(self, filename):
        """
        This plugin gets a dict of files, not just one file if it runs the command.
        We just need the xml.
        """
        if isinstance(filename, dict):
            filename = filename['xml']
        with open(filename, **self.open_options) as output:
            self.parseOutputString(output.read())
        if self._delete_temp_file:
            if isinstance(filename, dict):
                for _file in filename.values():
                    try:
                        os.remove(_file)
                    except Exception as e:
                        self.logger.error("Error on delete file: (%s) [%s]", _file, e)
            else:
                try:
                    os.remove(filename)
                except Exception as e:
                    self.logger.error("Error on delete file: (%s) [%s]", filename, e)

    def parseOutputString(self, output):
        """
        This method will discard the output the shell sends, it will read it
        from the xml where it expects it to be present.
        """
        parser = ArachniXmlParser(output)

        # Check xml parsed ok...
        if not parser.system:
            return

        self.hostname = self.getHostname(parser.system.url)
        if parser.plugins.ip:
            self.address = self.resolve_hostname(parser.plugins.ip)
        else:
            self.address = self.resolve_hostname(self.hostname)

        # Create host and interface
        host_id = self.createAndAddHost(self.address, hostnames=[self.hostname])

        # Create service
        service_id = self.createAndAddServiceToHost(
            host_id,
            self.protocol,
            'tcp',
            ports=[self.port],
            status='open',
            version='',
            description='')

        # Create issues.
        for issue in parser.issues:
            description = str(issue.description)
            resol = str(issue.remedy_guidance)

            references = issue.references
            cwe = []
            if issue.cwe != 'None':
                cwe.append('CWE-' + str(issue.cwe))
            if resol == 'None':
                resol = ''

            self.createAndAddVulnWebToService(
                host_id,
                service_id,
                name=issue.name,
                desc=description,
                data=issue.data,
                resolution=resol,
                ref=references,
                severity=issue.severity,
                website=self.hostname,
                path=issue.url,
                method=issue.method,
                pname=issue.var,
                params=issue.parameters,
                request=issue.request,
                response=issue.response,
                cwe=cwe
            )

        return

    def processCommandString(self, username, current_path, command_string):
        """
        Use bash to run sequentialy arachni and arachni_reporter
        """
        # Dont call the parent beacuse this plugin needs a different implementation
        if command_string.startswith("sudo"):
            params = " ".join(command_string.split()[2:])
        else:
            params = " ".join(command_string.split()[1:])
        self.vulns_data["command"]["params"] = params
        self.vulns_data["command"]["user"] = username
        self._output_file_path = {}
        self._delete_temp_file = True
        for ext in self._temp_file_extension:
            self._output_file_path[ext] = self._get_temp_file(extension=ext)
        afr_file_path = self._output_file_path['afr']
        xml_file_path = self._output_file_path['xml']
        report_arg_re = r"^.*(--report-save-path[=\s][^\s]+).*$"
        arg_match = re.match(report_arg_re, command_string)
        if arg_match is None:
            main_cmd = re.sub(r"(^.*?arachni)", r"\1 --report-save-path=%s" % afr_file_path, command_string)
        else:
            main_cmd = re.sub(arg_match.group(1), r"--report-save-path=%s" % afr_file_path, command_string)

        # add reporter
        cmd_prefix_match = re.match(r"(^.*?)arachni ", command_string)
        cmd_prefix = cmd_prefix_match.group(1)
        reporter_cmd = "{}{} --reporter=\"xml:outfile={}\" \"{}\"".format(cmd_prefix, "arachni_reporter", xml_file_path,
                                                                      afr_file_path)
        return "/usr/bin/env -- bash -c '{}  2>&1 && if [ -e \"{}\" ];then {} 2>&1;fi'".format(main_cmd,
                                                                                           afr_file_path,
                                                                                           reporter_cmd)

    def getHostname(self, url):

        # Strips protocol and gets hostname from URL.
        url_parse = urlparse(url)
        self.protocol = url_parse.scheme
        self.hostname = url_parse.netloc

        if self.protocol == 'https':
            self.port = 443
        elif self.protocol == 'http':
            if not self.port:
                self.port = 80

        return self.hostname


def createPlugin(*args, **kwargs):
    return ArachniPlugin(*args, **kwargs)
