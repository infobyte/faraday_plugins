import lxml.etree as ET

from faraday_plugins.plugins.repo.burp.plugin import Item, strtobool


def test_decode_binary_node_keeps_plain_text():
    node = ET.fromstring("<request base64='false'>plain text</request>")
    item = Item.__new__(Item)

    assert item.decode_binary_node(node) == "plain text"


def test_decode_binary_node_decodes_base64_text():
    node = ET.fromstring("<request base64='true'>cGxhaW4gdGV4dA==</request>")
    item = Item.__new__(Item)

    assert item.decode_binary_node(node) == "plain text"


def test_strtobool_rejects_invalid_values():
    try:
        strtobool("maybe")
    except ValueError as exc:
        assert "invalid truth value 'maybe'" == str(exc)
    else:
        raise AssertionError("ValueError was not raised")
