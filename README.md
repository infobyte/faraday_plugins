## Install

```shell script
pip install faraday-plugins
```

## Commands

> List Plugins

```shell script
faraday-plugins show
```

> Test autodetect plugin from command

```shell script
faraday-plugins detect-command "ping -c 4 www.google.com"
> Faraday Plugin: ping
```

> Test command with plugin

Optional params:

- -dr: Dont run, just show the generated command

```shell script
faraday-plugins process-command "ping -c4 www.google.com"
Running command:  ping -c4 www.google.com

PING www.google.com (216.58.222.36): 56 data bytes
64 bytes from 216.58.222.36: icmp_seq=0 ttl=54 time=11.144 ms
64 bytes from 216.58.222.36: icmp_seq=1 ttl=54 time=14.330 ms
64 bytes from 216.58.222.36: icmp_seq=2 ttl=54 time=11.997 ms
64 bytes from 216.58.222.36: icmp_seq=3 ttl=54 time=11.190 ms

--- www.google.com ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 11.144/12.165/14.330/1.295 ms

Faraday API json:
{
    "hosts": [
        {
            "ip": "216.58.222.36",
            "os": "unknown",
            "hostnames": [
                "www.google.com"
            ],
            "description": "",
            "mac": "00:00:00:00:00:00",
            "credentials": [],
            "services": [],
            "vulnerabilities": []
        }
    ],
    "command": {
        "tool": "ping",
        "command": "ping",
        "params": "-c4 www.google.com",
        "user": "aenima",
        "hostname": "",
        "start_date": "2020-05-05T23:09:39.656132",
        "duration": 56789,
        "import_source": "report"
    }
}
```

> Test autodetect plugin from report

```shell script
faraday-plugins detect-report /path/to/report.xml
```


> Test report with plugin

```shell script
faraday-plugins process-report /path/to/report.xml
```

> Process options:

Both process-xxx command have this optional parameters

- --plugin_id: If given will use that plugin instead of try to detect it
- --summary: If given will generate a summary of the findings instead of the result
- -cpf/--custom-plugins-folder: If given will also look for custom plugins if that path

NOTE: you can also use -cpf in **show** command to test if your custom plugins load ok

> Plugin Logger

To use it you must call ```self.logger.debug("some message")```

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


> More documentation here https://github.com/infobyte/faraday/wiki/Basic-plugin-development
