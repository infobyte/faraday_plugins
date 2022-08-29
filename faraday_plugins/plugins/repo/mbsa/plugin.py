"""
Faraday Penetration Test IDE
Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from faraday_plugins.plugins.plugin import PluginByExtension
import re
from datetime import datetime

__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Blas Moyano"
__status__ = "Development"


class MbsaParser:
    def __init__(self, log_output):
        self.computer_name = re.search('(Computer name:) (.*[A-Z])', log_output)
        self.ip = re.search(r'(IP address:) ([0-9]+(?:\.[0-9]+){3})', log_output)
        self.scan_date = re.search('(Scan date:) (.*[0-9])', log_output)
        self.issues = re.findall(r'Issue: .*', log_output)
        self.score = re.findall(r'Score: .*', log_output)
        self.result = re.findall(r'Result: .*', log_output)


class MbsaPlugin(PluginByExtension):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "MBSA"
        self.name = "Microsoft Baseline Security Analyzer"
        self.plugin_version = "1.0.1"
        self.version = "MBSA 1.0"
        self.framework_version = "1.0.0"
        self.extension = ".log"

    def parseOutputString(self, output):
        parser = MbsaParser(output)
        detail = ''
        i = 0
        issues_top = len(parser.issues)
        ip = '0.0.0.0'
        hostname = []
        run_date = None

        if parser.ip is not None:
            ip = parser.ip.group(2)
        if parser.computer_name is not None:
            hostname.append(parser.computer_name.group(2))
        if parser.scan_date is not None:
            run_date = datetime.strptime(parser.scan_date.group(2), '%Y/%m/%d %H:%M')

        host_id = self.createAndAddHost(
            ip,
            'Windows',
            hostnames=hostname)

        for issue in parser.issues:

            test = re.search(parser.issues[i], output)

            if i+1 != issues_top:
                test_issue = re.search(parser.issues[i+1], output)
            else:
                end = None
            try:
                start = test.end()
                end = test_issue.start()
            except:
                start = None

            if start is not None:
                if end is None:
                    result_info = output[start:]
                else:
                    result_info = output[start:end]
                    result_info.rstrip('\n')
                    result_info = result_info.replace(parser.score[i], '')
                    result_info = result_info.replace(parser.result[i], '')
                    result_info = result_info.strip()
                    if result_info:
                        detail = re.search('(Detail:)', result_info)
                        if not None:
                            detail = result_info
                            result_info = parser.result[i]

                    else:
                        detail = ''
                        result_info = parser.result[i]
            score = parser.score[i].replace('Score: ', '').strip()
            if score != 'Check passed':
                if score == 'Best practice' or score == 'Unable to scan':
                    severity = "info"
                elif score == 'Check failed (non-critical)':
                    severity = 'med'
                elif score == 'Check failed':
                    severity = 'high'
                else:
                    severity = 'info'

                self.createAndAddVulnToHost(
                    host_id,
                    issue.replace('Issue: ', '').strip(),
                    desc=result_info.replace('Result: ', '').strip(),
                    ref=None,
                    severity=severity,
                    data=detail,
                    run_date=run_date
                )

            i += 1


def createPlugin(*args, **kwargs):
    return MbsaPlugin(*args, **kwargs)
