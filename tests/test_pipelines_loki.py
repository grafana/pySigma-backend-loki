import pytest
from sigma.collection import SigmaCollection
from sigma.backends.loki import LogQLBackend
from sigma.pipelines.loki import loki_log_parser

def test_loki_grafana_pipeline():
    pipeline = loki_log_parser()
    backend = LogQLBackend(processing_pipeline=pipeline)
    sigma_rule = SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: test
                service: test
            detection:
                sel:
                    c-uri: /a/path/to/something
                    sc-status: 200
                condition: sel
        """)
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == ['{job=~".+"} | logfmt | path=`/a/path/to/something` and status=200']

