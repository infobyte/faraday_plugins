## Write you own plugins

> XML report plugin

```python
class XXXPLugin(PluginXMLFormat):

    def __init__(self):
        super().__init__()
        # Tags to be compared with the xml mail tag, can be a list or a string
        self.identifier_tag = ["tag1", "tag2"] 
        self.id = 'SOME_PLUGIN_ID' # Can't be repeated
        self.name = 'Some plugin name'
        self.plugin_version = 'X.X'
        # The extension is optional, only if its different than xml
        self.extension = ".xxx"    
```

> JSON report plugin

```python
class XXXPLugin(PluginJsonFormat):

    def __init__(self):
        super().__init__()
        # keys of the json that identify the report
        # you don't need to put all the keys, just some of them
        # it must be a set and will be compared as a subset of the json report keys
        self.json_keys = {"target_url", "effective_url", "interesting_findings"}
        self.id = 'SOME_PLUGIN_ID' # Can't be repeated
        self.name = 'Some plugin name'
        self.plugin_version = 'X.X'
        # The extension is optional, only if its different than json
        self.extension = ".xxx"    
```