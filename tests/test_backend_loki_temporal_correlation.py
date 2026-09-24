import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from sigma.backends.loki import LogQLBackend


@pytest.fixture
def loki_backend():
    return LogQLBackend()


def test_loki_temporal_correlation_two_rules_single_groupby(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule A
name: test_rule_a
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule B
name: test_rule_b
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: temporal
    rules:
        - test_rule_a
        - test_rule_b
    group-by:
        - fieldC
    timespan: 5m
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'sum by (fieldC) (count_over_time({job=~".+"} | logfmt | '
            "fieldA=~`(?i)^valueA$` [5m])) and "
            'sum by (fieldC) (count_over_time({job=~".+"} | logfmt | '
            "fieldB=~`(?i)^valueB$` [5m]))"
        )
    ]


def test_loki_temporal_correlation_multiple_groupby_fields(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule A
name: test_rule_a
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule B
name: test_rule_b
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: temporal
    rules:
        - test_rule_a
        - test_rule_b
    group-by:
        - fieldC
        - fieldD
    timespan: 10s
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'sum by (fieldC, fieldD) (count_over_time({job=~".+"} | logfmt | '
            "fieldA=~`(?i)^valueA$` [10s])) and "
            'sum by (fieldC, fieldD) (count_over_time({job=~".+"} | logfmt | '
            "fieldB=~`(?i)^valueB$` [10s]))"
        )
    ]


def test_loki_temporal_correlation_three_rules(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule A
name: test_rule_a
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule B
name: test_rule_b
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Rule C
name: test_rule_c
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldE: valueE
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: temporal
    rules:
        - test_rule_a
        - test_rule_b
        - test_rule_c
    group-by:
        - fieldC
    timespan: 1h
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'sum by (fieldC) (count_over_time({job=~".+"} | logfmt | '
            "fieldA=~`(?i)^valueA$` [1h])) and "
            'sum by (fieldC) (count_over_time({job=~".+"} | logfmt | '
            "fieldB=~`(?i)^valueB$` [1h])) and "
            'sum by (fieldC) (count_over_time({job=~".+"} | logfmt | '
            "fieldE=~`(?i)^valueE$` [1h]))"
        )
    ]


def test_loki_temporal_correlation_no_groupby(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule A
name: test_rule_a
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule B
name: test_rule_b
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: temporal
    rules:
        - test_rule_a
        - test_rule_b
    timespan: 5m
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'sum(count_over_time({job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` [5m])) and '
            'sum(count_over_time({job=~".+"} | logfmt | fieldB=~`(?i)^valueB$` [5m]))'
        )
    ]


def test_loki_temporal_correlation_field_mapping(loki_backend: LogQLBackend):
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
title: Test Rule A
name: test_rule_a
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule B
name: test_rule_b
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: temporal
    rules:
        - test_rule_a
        - test_rule_b
    group-by:
        - fieldB
    timespan: 5m
"""
    )
    loki_backend = LogQLBackend(processing_pipeline=pipeline)
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'sum by (fieldC) (count_over_time({job=~".+"} | logfmt | '
            "fieldA=~`(?i)^valueA$` [5m])) and "
            'sum by (fieldC) (count_over_time({job=~".+"} | logfmt | '
            "fieldC=~`(?i)^valueB$` [5m]))"
        )
    ]


def test_loki_temporal_correlation_aliases(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule A
name: test_rule_a
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule B
name: test_rule_b
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: temporal
    rules:
        - test_rule_a
        - test_rule_b
    aliases:
        user:
            test_rule_a: fieldUserA
            test_rule_b: fieldUserB
    group-by:
        - user
    timespan: 5m
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'sum by (user) (count_over_time({job=~".+"} | logfmt | '
            "fieldA=~`(?i)^valueA$` | label_format user=fieldUserA [5m])) and "
            'sum by (user) (count_over_time({job=~".+"} | logfmt | '
            "fieldB=~`(?i)^valueB$` | label_format user=fieldUserB [5m]))"
        )
    ]


def test_loki_temporal_correlation_unsupported_multi_query_rule(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule A
name: test_rule_a
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel1:
        fieldA: valueA
    sel2:
        fieldZ: valueZ
    condition:
        - sel1
        - sel2
---
title: Test Rule B
name: test_rule_b
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: temporal
    rules:
        - test_rule_a
        - test_rule_b
    group-by:
        - fieldC
    timespan: 5m
"""
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="single query"):
        loki_backend.convert(rules)


def test_loki_temporal_correlation_unsupported_partial_condition(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule A
name: test_rule_a
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule B
name: test_rule_b
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Rule C
name: test_rule_c
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldE: valueE
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: temporal
    rules:
        - test_rule_a
        - test_rule_b
        - test_rule_c
    group-by:
        - fieldC
    timespan: 5m
    condition:
        gte: 2
"""
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="all referenced rules"):
        loki_backend.convert(rules)


def test_loki_temporal_ordered_correlation_unsupported(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule A
name: test_rule_a
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule B
name: test_rule_b
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: temporal_ordered
    rules:
        - test_rule_a
        - test_rule_b
    group-by:
        - fieldC
    timespan: 5m
"""
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="[Oo]rdered"):
        loki_backend.convert(rules)


def test_loki_temporal_correlation_extended_condition_unsupported(loki_backend: LogQLBackend):
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule A
name: test_rule_a
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule B
name: test_rule_b
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Correlation
status: test
correlation:
    type: temporal
    rules:
        - test_rule_a
        - test_rule_b
    group-by:
        - fieldC
    timespan: 5m
    condition: "test_rule_a and test_rule_b"
"""
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="[Ee]xtended"):
        loki_backend.convert(rules)
