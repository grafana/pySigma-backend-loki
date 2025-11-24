import pytest
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation

from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection


@pytest.fixture
def loki_backend():
    return LogQLBackend()


def test_loki_default_event_count_no_field(loki_backend: LogQLBackend):
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
    timespan: 30s
    condition:
        eq: 42
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        'sum(count_over_time({job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` [30s])) == 42'
    ]


def test_loki_default_event_count_single_field(loki_backend: LogQLBackend):
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
    assert queries == [
        'sum by (fieldB) (count_over_time({job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` [5m])) >= 1'
    ]


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
    type: event_count
    rules:
        - test_rule
    group-by:
        - fieldB
        - fieldC
    timespan: 1d
    condition:
        lt: 100
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        'sum by (fieldB, fieldC) (count_over_time({job=~".+"} | logfmt | '
        "fieldA=~`(?i)^valueA$` [1d])) < 100"
    ]


def test_loki_default_event_count_field_mapping(loki_backend: LogQLBackend):
    pipeline = ProcessingPipeline(
        name="Test mapping fields in correlations",
        priority=20,
        items=[
            ProcessingItem(
                identifier="update_field_B_to_C",
                transformation=FieldMappingTransformation(
                    mapping={
                        "fieldB": "fieldC",
                    }
                ),
            ),
        ],
    )
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
        fieldB|contains: valueB
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
    timespan: 36h
    condition:
        lte: 5000
"""
    )
    loki_backend = LogQLBackend(processing_pipeline=pipeline)
    queries = loki_backend.convert(rules)
    assert queries == [
        'sum by (fieldC) (count_over_time({job=~".+"} | logfmt | '
        "fieldA=~`(?i)^valueA$` and fieldC=~`(?i).*valueB.*` [36h])) <= 5000"
    ]


def test_loki_default_event_count_log_source(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule
name: test_rule
status: test
logsource:
    category: network_connection
    product: windows
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
    timespan: 1d
    condition:
        gte: 100
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        'sum(count_over_time({job=~"eventlog|winlog|windows|fluentbit.*"} | json | '
        "fieldA=~`(?i)^valueA$` [1d])) >= 100"
    ]


def test_loki_default_event_count_absent_over_time_eq_0(loki_backend: LogQLBackend):
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
    timespan: 30s
    condition:
        eq: 0
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        'sum(absent_over_time({job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` [30s])) == 1'
    ]


def test_loki_default_event_count_absent_over_time_lt_1(loki_backend: LogQLBackend):
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
        lt: 1
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        'sum by (fieldB) (absent_over_time({job=~".+"} | logfmt | '
        "fieldA=~`(?i)^valueA$` [5m])) == 1"
    ]
