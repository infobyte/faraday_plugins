import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--performance", action="store_true", default=False, help="run performance tests"
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "performance: mark test as performance")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--performance"):
        # --performance given in cli: do not skip performance tests
        return
    performance = pytest.mark.skip(reason="need --performance option to run")
    for item in items:
        if "performance" in item.keywords:
            item.add_marker(performance)