import pytest
from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection


@pytest.fixture
def loki_backend():
    return LogQLBackend()


# Testing event count correlation rules
def test_loki_default_event_count_simple(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule
name: test_rule
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: event_count
    rules:
        - test_rule
    group-by:
        - fieldB
    timespan: 5m
    condition:
        gte: 1
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == ['sum by (fieldB) (count_over_time({job=~".+"} | logfmt | '
                       'fieldA=~`(?i)^valueA$` [5m])) >= 1']
