import pytest

from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection


@pytest.fixture
def loki_backend():
    return LogQLBackend()


def test_loki_default_value_count_no_group(loki_backend: LogQLBackend):
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
    type: value_count
    rules:
        - test_rule
    timespan: 30s
    condition:
        field: fieldB
        eq: 42
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == ['count without (fieldB) (sum by (fieldB) (count_over_time({job=~".+"} | '
                       'logfmt | fieldA=~`(?i)^valueA$` [30s]))) == 42']


def test_loki_default_value_count_single_group(loki_backend: LogQLBackend):
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
    type: value_count
    rules:
        - test_rule
    group-by:
        - fieldB
    timespan: 5m
    condition:
        field: fieldC
        gte: 1
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == ['count without (fieldC) (sum by (fieldB, fieldC) (count_over_time('
                       '{job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` [5m]))) >= 1']


def test_loki_default_event_count_multiple_fields(loki_backend: LogQLBackend):
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
    type: value_count
    rules:
        - test_rule
    group-by:
        - fieldB
        - fieldC
    timespan: 1d
    condition:
        field: fieldD
        lt: 100
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == ['count without (fieldD) (sum by (fieldB, fieldC, fieldD) (count_over_time('
                       '{job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` [1d]))) < 100']
