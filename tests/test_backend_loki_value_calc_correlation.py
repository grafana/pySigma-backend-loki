import pytest
from sigma.collection import SigmaCollection

from sigma.backends.loki import LogQLBackend


@pytest.fixture
def loki_backend():
    return LogQLBackend()


def test_loki_default_value_sum_no_group(loki_backend: LogQLBackend):
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
    type: value_sum
    rules:
        - test_rule
    timespan: 30s
    condition:
        field: fieldB
        gte: 1000
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'sum(sum_over_time({job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` | '
            "unwrap fieldB [30s])) >= 1000"
        )
    ]


def test_loki_default_value_sum_single_group(loki_backend: LogQLBackend):
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
    type: value_sum
    rules:
        - test_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        field: fieldB
        gte: 1000
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            "sum by (fieldC) (sum_over_time("
            '{job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` | unwrap fieldB [5m])) >= 1000'
        )
    ]


def test_loki_default_value_avg_no_group(loki_backend: LogQLBackend):
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
    type: value_avg
    rules:
        - test_rule
    timespan: 5m
    condition:
        field: fieldB
        gte: 1000
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'avg_over_time({job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` | '
            "unwrap fieldB [5m]) by () >= 1000"
        )
    ]


def test_loki_default_value_avg_single_group(loki_backend: LogQLBackend):
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
    type: value_avg
    rules:
        - test_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        field: fieldB
        gte: 1000
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'avg_over_time({job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` | '
            "unwrap fieldB [5m]) by (fieldC) >= 1000"
        )
    ]


def test_loki_default_value_median_no_group(loki_backend: LogQLBackend):
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
    type: value_median
    rules:
        - test_rule
    timespan: 5m
    condition:
        field: fieldB
        gte: 100
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'quantile_over_time(0.5, {job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` | '
            "unwrap fieldB [5m]) by () >= 100"
        )
    ]


def test_loki_default_value_median_single_group(loki_backend: LogQLBackend):
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
    type: value_median
    rules:
        - test_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        field: fieldB
        gte: 100
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'quantile_over_time(0.5, {job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` | '
            "unwrap fieldB [5m]) by (fieldC) >= 100"
        )
    ]


def test_loki_default_value_percentile_no_group(loki_backend: LogQLBackend):
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
    type: value_percentile
    rules:
        - test_rule
    timespan: 5m
    condition:
        field: fieldB
        percentile: 95
        gte: 500
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'quantile_over_time(0.95, {job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` | '
            "unwrap fieldB [5m]) by () >= 500"
        )
    ]


def test_loki_default_value_percentile_single_group(loki_backend: LogQLBackend):
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
    type: value_percentile
    rules:
        - test_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        field: fieldB
        percentile: 95
        gte: 500
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'quantile_over_time(0.95, {job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` | '
            "unwrap fieldB [5m]) by (fieldC) >= 500"
        )
    ]


def test_loki_default_value_percentile_missing_percentile(loki_backend: LogQLBackend):
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
    type: value_percentile
    rules:
        - test_rule
    timespan: 5m
    condition:
        field: fieldB
        gte: 500
"""
    )
    with pytest.raises(
        Exception,
        match="Percentile must be specified",
    ):
        loki_backend.convert(rules)
