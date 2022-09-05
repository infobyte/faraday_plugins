import re
import string
from urllib.parse import urljoin, urlparse

from faraday_plugins.plugins.plugin import PluginBase


class WfuzzPlugin(PluginBase):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "Wfuzz"
        self.name = "Wfuzz Plugin"
        self.plugin_version = "0.0.1"
        self.version = "2.2.11"
        self.options = None

        self.host = None
        self.port = None
        self.protocol = None
        self.fail = None
        self._command_regex = re.compile(r'^(wfuzz)\s+.*?')

    def parseData(self, output):

        data = {
            'target' : '',
            'findings' : []
        }
        for line in output:
            # remove stdout hidden chars
            line = ''.join([char for char in line if char in string.printable])
            line = line.strip('\r').replace('[0K', '').replace('[0m', '')
            if line.startswith('Target'):
                data['target'] = line[8:].rstrip()
                continue
            if line.startswith('0'):
                aux = line.split('  ')
                res = {}
                for item in aux:
                    if 'C=' in item:
                        res['response'] = int(item.replace('C=', ''))
                    elif 'L' in item and ' ' in item:
                        res['lines'] = int(item.replace('L', ''))
                    elif 'W' in item and ' ' in item:
                        res['words'] = int(item.replace('W', ''))
                    elif 'Ch' in item and ' ' in item:
                        res['chars'] = int(item.replace('Ch', ''))
                    else:
                        res['request'] = item.rstrip().replace('"', '')
                data['findings'].append(res)

        return data

    def parseOutputString(self, output):
        output_list = output.split('\n')
        info = self.parseData(output_list)

        target = info['target']
        target_url = urlparse(target)
        port = 80

        if target_url.scheme == 'https':
            port = 443
        custom_port = target_url.netloc.split(':')
        if len(custom_port) > 1:
            port = custom_port[1]

        host_id = self.createAndAddHost(target)

        service_id = self.createAndAddServiceToHost(host_id,name="http",protocol="tcp", ports=[port] )

        for item in info['findings']:
            path = item['request']
            status = item['response']
            url = urljoin(target, path)
            lines = item['lines']
            chars = item['chars']
            words = item['words']
            name = f"Wfuzz found: {path} with status {status} on url {url}"
            desc = 'Wfuzz found a response with status {status}. Response contains: \n* {words} words \n* {lines} ' \
                   'lines \n* {chars} chars'.format(words=words, lines=lines, chars=chars, status=status)
            self.createAndAddVulnWebToService(host_id, service_id, name, desc, severity="info", website=target,
                                              path=path)


def createPlugin(*args, **kwargs):
    return WfuzzPlugin(*args, **kwargs)
