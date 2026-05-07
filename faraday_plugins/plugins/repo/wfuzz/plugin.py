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

    # ANSI escape sequence stripper, e.g. "\x1b[0K", "\x1b[31m"
    _ansi_re = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

    # wfuzz 2.4+ default-table line:
    #   000000001:   301     0 L     0 W   0 Ch     "admin"
    # wfuzz <2.3 line:
    #   000001:  C=200      1 L      2 W       57 Ch      "admin"
    _row_re = re.compile(
        r'^(?P<id>\d+):\s+'
        r'(?:C=)?(?P<status>\d{3})\s+'
        r'(?P<lines>\d+)\s*L\s+'
        r'(?P<words>\d+)\s*W\s+'
        r'(?P<chars>\d+)\s*Ch\s+'
        r'"(?P<request>[^"]*)"'
    )

    def parseData(self, output):
        data = {'target': '', 'findings': []}
        # Cheap pre-clean: drop ANSI sequences and CR. Wfuzz also emits the
        # status table on a single line per result, but versions differ on
        # whether they wrap; splitting on ESC[K gives one row per match.
        if isinstance(output, list):
            output = "\n".join(output)
        cleaned = self._ansi_re.sub('', output).replace('\r', '')
        for raw_line in cleaned.split('\n'):
            line = raw_line.strip()
            if line.startswith('Target:'):
                data['target'] = line[len('Target:'):].strip()
                continue
            m = self._row_re.match(line)
            if m:
                data['findings'].append({
                    'response': int(m.group('status')),
                    'lines': int(m.group('lines')),
                    'words': int(m.group('words')),
                    'chars': int(m.group('chars')),
                    'request': m.group('request'),
                })
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
