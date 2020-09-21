"""
Faraday Penetration Test IDE
Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from faraday_plugins.plugins.plugin import PluginByExtension
import re
import os
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
        pass


class MbsaPlugin(PluginByExtension):
    def __init__(self):
        super().__init__()
        self.id = "MBSA"
        self.name = "Microsoft Baseline Security Analyzer"
        self.plugin_version = "1.0.1"
        self.version = "MBSA 1.0"
        self.framework_version = "1.0.0"
        self.extension = ".log"

    def parseOutputString(self, output):

        computer_name = re.search('(Computer name:) (.*[A-Z])', output)
        ip = re.search('(IP address:) ([0-9]+(?:\.[0-9]+){3})', output)
        scan_date = re.search('(Scan date:) (.*[0-9])', output)
        issues = re.findall(r'Issue: .*', output)
        score = re.findall(r'Score: .*', output)
        result = re.findall(r'Result: .*', output)
        detail = ''
        i = 0
        issues_top = len(issues)

        host_id = self.createAndAddHost(
            ip.group(2),
            'Windows',
            hostnames=[computer_name.group(2)])

        for issue in issues:

            test = re.search(issues[i], output)

            if i+1 != issues_top:
                test_issue = re.search(issues[i+1], output)
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
                    result_info = result_info.replace(score[i], '')
                    result_info = result_info.replace(result[i], '')
                    result_info = result_info.strip()
                    if result_info:
                        print("ntro")
                        detail = re.search('(Detail:)', result_info)
                        if not None:
                            detail = result_info
                            result_info = result[i]

                    else:
                        detail = ''
                        result_info = result[i]

            self.createAndAddVulnToHost(host_id,
                                        issue.replace('Issue: ', ''),
                                        desc=score[i].replace('Score: ', ''),
                                        ref=None,
                                        resolution=result_info.replace('Result: ', ''),
                                        data=detail,
                                        run_date=datetime.strptime(scan_date.group(2), '%Y/%m/%d %H:%M'))

            i += 1


def createPlugin():
    return MbsaPlugin()
