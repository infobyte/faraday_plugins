## Install

```shell script
pip install faraday-plugins
```

## Commands

### List Plugins

List all plugins and if its compatible with command or/and report

Optional params:

- -cpf / --custom-plugins-folder PATH: If given will also look for custom plugins on that path

```shell script
faraday-plugins list-plugins
```

### Test autodetect plugin from command

```shell script
faraday-plugins detect-command "ping -c 4 www.google.com"

Faraday Plugin: ping
```

### Test process command with plugin

Optional params:

- --plugin_id PLUGIN_ID: Dont detect the plugin, use this one
- -cpf / --custom-plugins-folder PATH: If given will also look for custom plugins on that path
- -dr / --dont-run: Dont run, just show the generated command
- -o / --output-file PATH: send json outout to file instead of stdout
- -sh / --show-output: show the output of the command

```shell script
faraday-plugins process-command "ping -c4 www.google.com"
{
    "hosts": [
        {
            "ip": "216.58.202.36",
            "os": "unknown",
            "hostnames": [
                "www.google.com"
            ],
            "description": "",
            "mac": null,
            "credentials": [],
            "services": [],
            "vulnerabilities": [],
            "tags": []
        }
    ],
    "command": {
        "tool": "ping",
        "command": "ping",
        "params": "-c4 www.google.com",
        "user": "user",
        "hostname": "",
        "start_date": "2020-06-19T17:02:37.982293",
        "duration": 39309,
        "import_source": "shell"
    }
}
```

### Test autodetect plugin from report

```shell script
faraday-plugins detect-report /path/to/report.xml

Faraday Plugin: Nmap
```

### Test report with plugin

Optional params:

- --plugin_id PLUGIN_ID: Dont detect the plugin, use this one
- -cpf / --custom-plugins-folder PATH: If given will also look for custom plugins on that path

```shell script
faraday-plugins process-report /path/to/nmap_report.xml

{
    "hosts": [
        {
            "ip": "192.168.66.1",
            "os": "unknown",
            "hostnames": [],
            "description": "",
            "mac": "00:00:00:00:00:00",
            "credentials": [],
            "services": [
                {
                    "name": "domain",
                    "protocol": "tcp",
                    "port": 53,
                    "status": "open",
                    "version": "",
                    "description": "domain",
                    "credentials": [],
                    "vulnerabilities": [],
                    "tags": []
                },
                {
                    "name": "netbios-ssn",
                    "protocol": "tcp",
                    "port": 139,
                    "status": "open",
                    "version": "",
                    "description": "netbios-ssn",
                    "credentials": [],
                    "vulnerabilities": [],
                    "tags": []
                }
            ],
            "vulnerabilities": [],
            "tags": []
        }
    ],
    "command": {
        "tool": "Nmap",
        "command": "Nmap",
        "params": "/path/to/nmap_report.xml",
        "user": "user",
        "hostname": "",
        "start_date": "2020-06-19T17:22:11.608134",
        "duration": 1233,
        "import_source": "report"
    }
}
```

## Plugin Logger

To use it you must call `self.logger.debug("some message")`

```shell script
export PLUGIN_DEBUG=1
faraday-plugins proces-report /path/to/report.xml
2019-11-15 20:37:03,355 - faraday.faraday_plugins.plugins.manager - INFO [manager.py:113 - _load_plugins()]  Loading Native Plugins...
2019-11-15 20:37:03,465 - faraday.faraday_plugins.plugins.manager - DEBUG [manager.py:123 - _load_plugins()]  Load Plugin [acunetix]
2019-11-15 20:37:03,495 - faraday.faraday_plugins.plugins.manager - DEBUG [manager.py:123 - _load_plugins()]  Load Plugin [amap]
2019-11-15 20:37:03,549 - faraday.faraday_plugins.plugins.manager - DEBUG [manager.py:123 - _load_plugins()]  Load Plugin [appscan]
2019-11-15 20:37:03,580 - faraday.faraday_plugins.plugins.manager - DEBUG [manager.py:123 - _load_plugins()]  Load Plugin [arachni]
2019-11-15 20:37:03,613 - faraday.faraday_plugins.plugins.manager - DEBUG [manager.py:123 - _load_plugins()]  Load Plugin [arp_scan]
2019-11-15 20:37:03,684 - faraday.faraday_plugins.plugins.manager - DEBUG [manager.py:123 - _load_plugins()]  Load Plugin [beef]
2019-11-15 20:37:03,714 - faraday.faraday_plugins.plugins.manager - DEBUG [manager.py:123 - _load_plugins()]  Load Plugin [brutexss]
2019-11-15 20:37:03,917 - faraday.faraday_plugins.plugins.manager - DEBUG [manager.py:123 - _load_plugins()]  Load Plugin [burp]
2019-11-15 20:37:03,940 - faraday.faraday_plugins.plugins.manager - DEBUG [manager.py:123 - _load_plugins()]  Load Plugin [dig]
...
```

More documentation here https://docs.faradaysec.com/Basic-plugin-development/
