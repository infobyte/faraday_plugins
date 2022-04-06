from typing import List
from urllib.parse import urlparse
import re


def extract_params_from_uri(uri):
    f = re.compile(r"(\w+)=")
    params = re.findall(f, uri)
    return params if params else ''


class Uri:
    def __init__(self, uri):
        self.uri = uri
        self.parsed_url = urlparse(uri)
        self.query = self.parsed_url.query
        self.path = self.parsed_url.path
        self.params = extract_params_from_uri(uri)


class Instance:
    def __init__(self, node):
        self.node = node

    @property
    def uri(self) -> Uri:
        return Uri(self.node.get('uri')) if self.node is not None else ""

    @property
    def method(self) -> str:
        return self.node.get('method') if self.node is not None else ""

    @property
    def param(self) -> str:
        return self.node.get('param') if self.node is not None else ""

    @property
    def attack(self) -> str:
        return self.node.get('attack') if self.node is not None else ""

    @property
    def evidence(self) -> str:
        return self.node.get('evidence') if self.node is not None else ""

    @property
    def request_header(self) -> str:
        return self.node.get('request-header') if self.node is not None else ""

    @property
    def request(self) -> str:
        return self.node.get('request-body') if self.node is not None else ""

    @property
    def response_header(self) -> str:
        return self.node.get('response-header') if self.node is not None else ""

    @property
    def response(self) -> str:
        return self.node.get('response-body') if self.node is not None else ""


class Alert:
    def __init__(self, node):
        self.node = node

    @property
    def plugin_id(self) -> str:
        return self.node.get('pluginid') if self.node is not None else ""

    @property
    def alert_id(self) -> str:
        return self.node.get('alertRef') if self.node is not None else ""

    @property
    def name(self) -> str:
        return self.node.get('name') if self.node is not None else ""

    @property
    def riskcode(self) -> str:
        return self.node.get('riskcode') if self.node is not None else ""

    @property
    def confidence(self) -> str:
        return self.node.get('confidence') if self.node is not None else ""

    @property
    def riskdesc(self) -> str:
        return self.node.get('riskdesc') if self.node is not None else ""

    @property
    def desc(self) -> str:
        return self.node.get('desc') if self.node is not None else ""

    @property
    def instances(self) -> List[Instance]:
        return [Instance(i) for i in self.node.get('instances', [])]

    @property
    def count(self) -> str:
        return self.node.get('count') if self.node is not None else ""

    @property
    def solution(self) -> str:
        return self.node.get('solution') if self.node is not None else ""

    @property
    def otherinfo(self) -> str:
        return self.node.get('otherinfo') if self.node is not None else ""

    @property
    def reference(self) -> str:
        return self.node.get('reference') if self.node is not None else ""

    @property
    def cwe(self) -> str:
        return self.node.get('cweid') if self.node is not None else ""

    @property
    def wasc(self) -> str:
        return self.node.get('wascid') if self.node is not None else ""

    @property
    def sourceid(self) -> str:
        return self.node.get("sourceid") if self.node is not None else ""


class Site:
    def __init__(self, node):
        self.node = node

    @property
    def host(self) -> str:
        return self.node.get('@host') if self.node is not None else ""

    @property
    def name(self) -> str:
        return self.node.get('@name') if self.node is not None else ""

    @property
    def port(self) -> str:
        return self.node.get('@port') if self.node is not None else ""

    @property
    def ssl(self) -> str:
        return self.node.get('@ssl') if self.node is not None else ""

    @property
    def alerts(self) -> List[Alert]:
        return [Alert(i) for i in self.node.get('alerts', [])]


class ZapJsonParser:
    def __init__(self, node):
        self.node = node

    @property
    def sites(self) -> List[Site]:
        return [Site(i) for i in self.node.get('site', [])]
