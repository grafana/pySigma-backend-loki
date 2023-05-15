import pytest
from sigma.plugins import InstalledSigmaPlugins
from sigma.backends.loki import LogQLBackend
from sigma.pipelines.loki import (
    loki_grafana_logfmt,
    loki_promtail_sysmon_message,
    loki_okta_system_log_json,
)


@pytest.fixture
def installed() -> InstalledSigmaPlugins:
    return InstalledSigmaPlugins.autodiscover()


def test_auto_discover_loki_be(installed: InstalledSigmaPlugins):
    assert "loki" in installed.backends
    assert installed.backends["loki"] is LogQLBackend


def test_auto_discover_loki_pipelines(installed: InstalledSigmaPlugins):
    pipelines = [
        loki_grafana_logfmt,
        loki_promtail_sysmon_message,
        loki_okta_system_log_json,
    ]
    print(installed.pipelines)
    for pipeline in pipelines:
        name = pipeline.__name__
        assert name in installed.pipelines
        assert installed.pipelines[name] == pipeline
