import pytest

from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection

from sigma.pipelines.loki import loki_okta_system_log


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
    assert queries == [
        'count without (fieldB) (sum by (fieldB) (count_over_time({job=~".+"} | '
        "logfmt | fieldA=~`(?i)^valueA$` [30s]))) == 42"
    ]


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
    assert queries == [
        "count without (fieldC) (sum by (fieldB, fieldC) (count_over_time("
        '{job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` [5m]))) >= 1'
    ]


def test_loki_default_value_count_multiple_fields(loki_backend: LogQLBackend):
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
    assert queries == [
        "count without (fieldD) (sum by (fieldB, fieldC, fieldD) (count_over_time("
        '{job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` [1d]))) < 100'
    ]


def test_loki_okta_country_count():
    pipeline = loki_okta_system_log()
    # Note: using
    rules = SigmaCollection.from_yaml(
        """
title: Okta User Activity With Country Defined
id: 79bbc335-7ab0-4316-a17b-30c85f7f0595
status: experimental
description: Detects any Okta activity that includes a country
references:
    - https://developer.okta.com/docs/reference/api/system-log/
author: kelnage
date: 2024-08-01
logsource:
    product: okta
    service: okta
detection:
    selection:
        actor.alternateid|exists: true
        client.geographicalcontext.country|exists: true
    condition: selection
falsepositives:
    - If a user requires an anonymising proxy due to valid justifications.
level: high
---
title: Okta User Activity Across Multiple Countries
id: a8c75573-8513-40c6-85a6-818b7c58a601
author: kelnage
date: 2024-08-01
status: experimental
correlation:
    type: value_count
    rules:
        - 79bbc335-7ab0-4316-a17b-30c85f7f0595
    group-by:
        - actor.alternateid
    timespan: 1h
    condition:
        field: client.geographicalcontext.country
        gt: 1
level: high
"""
    )
    loki_backend = LogQLBackend(processing_pipeline=pipeline)
    queries = loki_backend.convert(rules)
    assert queries == [
        "count without (event_client_geographicalContext_country) "
        "(sum by (event_actor_alternateId, "
        "event_client_geographicalContext_country) "
        '(count_over_time({job=~".+"} | json | event_actor_alternateId!="" and '
        'event_client_geographicalContext_country!="" [1h]))) '
        "> 1"
    ]
