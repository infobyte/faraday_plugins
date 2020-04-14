from faraday_plugins.plugins.plugin import PluginBase


def test_get_host_cache_id_with_same_host():
    host_1 = {'ip': '127.0.0.1'}
    host_2 = {'ip': '127.0.0.1', 'description': 'test desc'}
    cache_id_1 = PluginBase.get_host_cache_id(host_1)
    cache_id_2 = PluginBase.get_host_cache_id(host_2)

    assert cache_id_1 == cache_id_2


def test_get_host_cache_id_with_diffent_ip():
    host_1 = {'ip': '127.0.0.1'}
    host_2 = {'ip': '192.168.0.1', 'description': 'test desc'}
    cache_id_1 = PluginBase.get_host_cache_id(host_1)
    cache_id_2 = PluginBase.get_host_cache_id(host_2)

    assert cache_id_1 != cache_id_2


def test_get_host_service_cache_id_same_objects():
    host_1 = {'ip': '127.0.0.1'}
    host_cache_id_1 = PluginBase.get_host_cache_id(host_1)
    service_1 = {'protocol': 'tcp', 'port': 80}
    host_2 = {'ip': '127.0.0.1'}
    host_cache_id_2 = PluginBase.get_host_cache_id(host_2)
    service_2 = {'protocol': 'tcp', 'port': 80}

    cache_1 = PluginBase.get_host_service_cache_id(host_cache_id_1, service_1)
    cache_2 = PluginBase.get_host_service_cache_id(host_cache_id_2, service_2)

    assert cache_1 == cache_2


def test_get_host_service_cache_id_different_host():
    host_1 = {'ip': '127.0.0.1'}
    host_cache_id_1 = PluginBase.get_host_cache_id(host_1)
    service_1 = {'protocol': 'tcp', 'port': 80}
    host_2 = {'ip': '192.168.0.1'}
    host_cache_id_2 = PluginBase.get_host_cache_id(host_2)
    service_2 = {'protocol': 'tcp', 'port': 80}

    cache_1 = PluginBase.get_host_service_cache_id(host_cache_id_1, service_1)
    cache_2 = PluginBase.get_host_service_cache_id(host_cache_id_2, service_2)

    assert cache_1 != cache_2


def test_get_host_vuln_cache_id_severity_does_not_affect_duplicate():
    host_1 = {'ip': '127.0.0.1'}
    host_cache_id_1 = PluginBase.get_host_cache_id(host_1)
    vuln_1 = {'name': 'test', 'desc': 'test', 'severity': 'low'}

    host_2 = {'ip': '127.0.0.1'}
    host_cache_id_2 = PluginBase.get_host_cache_id(host_2)
    vuln_2 = {'name': 'test', 'desc': 'test', 'severity': 'high'}


    cache_1 = PluginBase.get_host_vuln_cache_id(host_cache_id_1, vuln_1)
    cache_2 = PluginBase.get_host_vuln_cache_id(host_cache_id_2, vuln_2)

    assert cache_1 == cache_2


def test_get_host_vuln_cache_id_description_makes_different_cache_ids():
    host_1 = {'ip': '127.0.0.1'}
    host_cache_id_1 = PluginBase.get_host_cache_id(host_1)
    vuln_1 = {'name': 'test', 'desc': 'test', 'severity': 'low'}

    host_2 = {'ip': '127.0.0.1'}
    host_cache_id_2 = PluginBase.get_host_cache_id(host_2)
    vuln_2 = {'name': 'test', 'new desc': 'test', 'severity': 'high'}


    cache_1 = PluginBase.get_host_vuln_cache_id(host_cache_id_1, vuln_1)
    cache_2 = PluginBase.get_host_vuln_cache_id(host_cache_id_2, vuln_2)

    assert cache_1 != cache_2


def test_get_service_vuln_cache_id_severity_does_not_affect_cache_id():
    host_1 = {'ip': '127.0.0.1'}
    host_cache_id_1 = PluginBase.get_host_cache_id(host_1)
    service_1 = {'protocol': 'tcp', 'port': 80}

    host_2 = {'ip': '127.0.0.1'}
    host_cache_id_2 = PluginBase.get_host_cache_id(host_2)
    host_2 = {'ip': '127.0.0.1'}
    host_cache_id_2 = PluginBase.get_host_cache_id(host_2)
    service_2 = {'protocol': 'tcp', 'port': 80}

    service_cache_1 = PluginBase.get_host_service_cache_id(host_cache_id_1, service_1)
    service_cache_2 = PluginBase.get_host_service_cache_id(host_cache_id_2, service_2)

    vuln_2 = {'name': 'test', 'desc': 'test', 'severity': 'high', 'method': 'GET'}
    vuln_1 = {'name': 'test', 'desc': 'test', 'severity': 'low', 'method': 'GET'}

    cache_1 = PluginBase.get_service_vuln_cache_id(host_cache_id_1, service_cache_1, vuln_1)
    cache_2 = PluginBase.get_service_vuln_cache_id(host_cache_id_2, service_cache_2, vuln_2)

    assert cache_1 == cache_2

def test_get_service_vuln_cache_id_with_different_service_return_different_id():
    host_1 = {'ip': '127.0.0.1'}
    host_cache_id_1 = PluginBase.get_host_cache_id(host_1)
    service_1 = {'protocol': 'tcp', 'port': 80}

    host_2 = {'ip': '127.0.0.1'}
    host_cache_id_2 = PluginBase.get_host_cache_id(host_2)
    host_2 = {'ip': '127.0.0.1'}
    host_cache_id_2 = PluginBase.get_host_cache_id(host_2)
    service_2 = {'protocol': 'tcp', 'port': 22}

    service_cache_1 = PluginBase.get_host_service_cache_id(host_cache_id_1, service_1)
    service_cache_2 = PluginBase.get_host_service_cache_id(host_cache_id_2, service_2)

    vuln_2 = {'name': 'test', 'desc': 'test', 'severity': 'high', 'method': 'GET'}
    vuln_1 = {'name': 'test', 'desc': 'test', 'severity': 'low', 'method': 'GET'}

    cache_1 = PluginBase.get_service_vuln_cache_id(host_cache_id_1, service_cache_1, vuln_1)
    cache_2 = PluginBase.get_service_vuln_cache_id(host_cache_id_2, service_cache_2, vuln_2)

    assert cache_1 != cache_2