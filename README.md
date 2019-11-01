## Install

```shell script
cd faraday-plugins
python setup.py install
```

## Commands

> List Plugins

```shell script
python -m faraday_plugins list
```

> Test autodetect plugin from report

```shell script
python -m faraday_plugins detect /path/to/report.xml
```


> Test report with plugin

```shell script
python -m faraday_plugins process appscan /path/to/report.xml
```

