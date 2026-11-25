import pytest

from pycrashreport import crash_report


@pytest.fixture(autouse=True)
def no_host_device_support(monkeypatch):
    """Keep reports from being named by whatever Xcode DeviceSupport the host happens to hold."""
    monkeypatch.setattr(
        crash_report, "find_device_support_symbols", lambda *_args, **_kwargs: None
    )


@pytest.fixture(autouse=True)
def no_host_symbol_server(monkeypatch):
    """Keep reports from asking the symbolicator server the host happens to be set up with."""
    monkeypatch.delenv(crash_report.SERVER_ENVVAR, raising=False)
