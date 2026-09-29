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


def test_loki_temporal_ordered_extended_condition_unsupported(loki_backend: LogQLBackend):
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
    condition: "test_rule_a and test_rule_b"
"""
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="[Oo]rdered"):
        loki_backend.convert(rules)


def test_loki_temporal_correlation_nested_value_count_correlation(loki_backend: LogQLBackend):
    """A temporal correlation whose referenced rule is itself a value_count correlation
    must use the inner correlation's already-produced metric query directly, without
    wrapping it in a second ``count_over_time`` — that wrap produces invalid LogQL."""
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule Base
name: test_rule_base
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule Other
name: test_rule_other
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Inner Value Count Correlation
name: test_inner_value_count
status: test
correlation:
    type: value_count
    rules:
        - test_rule_base
    group-by:
        - user
    timespan: 10m
    condition:
        gte: 3
        field: region
---
title: Test Outer Temporal
status: test
correlation:
    type: temporal
    rules:
        - test_inner_value_count
        - test_rule_other
    group-by:
        - user
    timespan: 15m
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            "count without (region) (sum by (user, region) (count_over_time("
            '{job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` [10m]))) >= 3'
        ),
        (
            "count without (region) (sum by (user, region) (count_over_time("
            '{job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` [10m]))) >= 3'
            " and "
            'sum by (user) (count_over_time({job=~".+"} | logfmt | '
            "fieldB=~`(?i)^valueB$` [15m]))"
        ),
    ]


def test_loki_temporal_correlation_nested_event_count_correlation(loki_backend: LogQLBackend):
    """A temporal correlation whose referenced rule is itself an event_count correlation
    must use the inner correlation's already-produced metric query directly."""
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule Base
name: test_rule_base
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule Other
name: test_rule_other
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Inner Event Count Correlation
name: test_inner_event_count
status: test
correlation:
    type: event_count
    rules:
        - test_rule_base
    group-by:
        - user
    timespan: 10m
    condition:
        gte: 5
---
title: Test Outer Temporal
status: test
correlation:
    type: temporal
    rules:
        - test_inner_event_count
        - test_rule_other
    group-by:
        - user
    timespan: 15m
"""
    )
    queries = loki_backend.convert(rules)
    assert queries == [
        (
            'sum by (user) (count_over_time({job=~".+"} | logfmt | '
            "fieldA=~`(?i)^valueA$` [10m])) >= 5"
        ),
        (
            'sum by (user) (count_over_time({job=~".+"} | logfmt | '
            "fieldA=~`(?i)^valueA$` [10m])) >= 5"
            " and "
            'sum by (user) (count_over_time({job=~".+"} | logfmt | '
            "fieldB=~`(?i)^valueB$` [15m]))"
        ),
    ]


def test_loki_temporal_correlation_nested_correlation_with_alias_unsupported(
    loki_backend: LogQLBackend,
):
    """Aliases against a nested correlation reference would need label_format applied
    to a metric expression, which is not valid LogQL — reject with a clear error."""
    rules = SigmaCollection.from_yaml(
        """
title: Test Rule Base
name: test_rule_base
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: valueA
    condition: sel
---
title: Test Rule Other
name: test_rule_other
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB: valueB
    condition: sel
---
title: Test Inner Event Count Correlation
name: test_inner_event_count
status: test
correlation:
    type: event_count
    rules:
        - test_rule_base
    group-by:
        - userA
    timespan: 10m
    condition:
        gte: 5
---
title: Test Outer Temporal
status: test
correlation:
    type: temporal
    rules:
        - test_inner_event_count
        - test_rule_other
    aliases:
        user:
            test_inner_event_count: userA
            test_rule_other: userB
    group-by:
        - user
    timespan: 15m
"""
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="[Aa]lias"):
        loki_backend.convert(rules)
