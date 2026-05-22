import pytest
from sigma.collection import SigmaCollection

from sigma.backends.loki import LogQLBackend
from sigma.pipelines.loki import loki_okta_system_log, pipelines


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


def test_request_path_dotted():
    rules = SigmaCollection.from_yaml(
        """
title: Sanitize test
id: 7fbad3c7-7b5d-4362-9581-c814ca975b2f
status: experimental
description: Tests correlation with field value that should be sanitized
author: TEST_RULE
date: 2026-05-20
correlation:
    type: value_count
    rules:
        - a3ecb779-194e-4354-8dad-0fab37346670
    group-by:
        - auth.display_name
    timespan: 1m
    condition:
        field: request.path
        gt: 5
level: high
---
title: Sanitize test base
id: a3ecb779-194e-4354-8dad-0fab37346670
status: experimental
description: Tests sanitization of fields
author: TEST_RULE
date: 2026-05-20
tags:
    - attack.discovery
    - attack.t1083
    - attack.credential_access
logsource:
    product: test
    service: test
detection:
    selection:
        request.type: "response"
        request.op: "read"
    condition: selection
level: informational
        """
    )

    loki_backend = LogQLBackend()
    queries = loki_backend.convert(rules)
    assert queries == [
        'count without (request_path) (sum by (auth_display_name, request_path) (count_over_time({job=~".+"} | logfmt | request_type=~`(?i)^response$` and request_op=~`(?i)^read$` [1m]))) > 5'
    ]
