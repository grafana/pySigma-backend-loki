import pytest
from sigma.plugins import InstalledSigmaPlugins
from sigma.backends.loki import LogQLBackend
from sigma.pipelines.loki import (
    loki_grafana_logfmt,
    loki_promtail_sysmon,
    loki_okta_system_log,
)


@pytest.fixture
def installed() -> InstalledSigmaPlugins:
    return InstalledSigmaPlugins.autodiscover()


def test_auto_discover_loki_backend(installed: InstalledSigmaPlugins):
    assert "loki" in installed.backends
    assert installed.backends["loki"] is LogQLBackend


def test_auto_discover_loki_pipelines(installed: InstalledSigmaPlugins):
    loki_pipelines = [
        loki_grafana_logfmt,
        loki_promtail_sysmon,
        loki_okta_system_log,
    ]
    for pipeline in loki_pipelines:
        assert pipeline.__name__ in installed.pipelines
        assert installed.pipelines[pipeline.__name__] == pipeline
