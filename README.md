## Install

```shell script
pip install faraday-plugins
```

## Commands

> List Plugins

```shell script
python -m faraday_plugins list
```

> Test autodetect plugin from report

```shell script
python -m faraday_plugins detect-report /path/to/report.xml
```


> Test report with plugin

```shell script
python -m faraday_plugins process-report appscan /path/to/report.xml
```

> Test autodetect plugin from command

```shell script
python -m faraday_plugins detect-command "ping -c 4 www.google.com"
```


> Test command with plugin

Optional params:

- -t: Timeout to wait to command to finish
- -d: If the command uses a temp file, delete it after
- -dr: Dont run, just show the generated command
```shell script
python -m faraday_plugins process-command nmap "nmap 192.168.1.1" -t 60 -d
```

> Custom Plugins

You can load custom plugins from a specific path with the ```-cpf or --custom-plugins-folder``` parameter
```shell script
python -m faraday_plugins process custom_plugin /path/to/report.xml -cpf /path/to/custom_plugins/
```

> Plugin Logger

To use it you must call ```self.logger.debug("some message")```

```shell script
export PLUGIN_DEBUG=1
python -m faraday_plugins proces-report appscan /path/to/report.xml
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
