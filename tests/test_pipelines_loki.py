import pytest
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection
from sigma.processing.transformations import transformations, FieldMappingTransformation
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.loki import (
    LokiCustomAttributes,
    SetCustomAttributeTransformation,
    CustomLogSourceTransformation,
    loki_grafana_logfmt,
    loki_promtail_sysmon,
    loki_okta_system_log,
)


@pytest.fixture
def sigma_rules() -> SigmaCollection:
    return SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                product: test
                service: test
            detection:
                sel:
                    msg: testing
                condition: sel
        """
    )


def test_transformations_contains_custom_attribute():
    assert "set_custom_attribute" in transformations
    assert transformations["set_custom_attribute"] == SetCustomAttributeTransformation


def test_loki_grafana_pipeline():
    pipeline = loki_grafana_logfmt()
    backend = LogQLBackend(processing_pipeline=pipeline)
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                product: test
                service: test
            detection:
                sel-path:
                    - c-uri: /a/path/to/something
                    - cs-uri-query: /a/different/path
                sel:
                    sc-status: 200
                condition: all of sel*
        """
    )
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == [
        '{job=~".+"} | logfmt | (path=~`(?i)^/a/path/to/something$`'
        " or path=~`(?i)^/a/different/path$`) and status=200"
    ]


def test_windows_grafana_pipeline():
    pipeline = loki_promtail_sysmon()
    backend = LogQLBackend(processing_pipeline=pipeline)
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                product: windows
                service: sysmon
            detection:
                sel:
                    Image|endswith: .exe
                    EventID: 1
                condition: sel
        """
    )
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == [
        '{job=~"eventlog|winlog|windows|fluentbit.*"} | json '
        '| label_format Message=`{{ .message | replace "\\\\" "\\\\\\\\" | replace "\\"" "\\\\\\"" }}` '  # noqa: E501
        '| line_format `{{ regexReplaceAll "([^:]+): ?((?:[^\\\\r]*|$))(\\r\\n|$)" .Message "${1}=\\"${2}\\" "}}` '  # noqa: E501
        "| logfmt | Image=~`(?i).*\\.exe$` and event_id=1"
    ]


def test_okta_json_pipeline():
    pipeline = loki_okta_system_log()
    backend = LogQLBackend(processing_pipeline=pipeline)
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                product: okta
                service: okta
            detection:
                sel:
                    eventType:
                        - policy.lifecycle.update
                        - policy.lifecycle.delete
                    legacyeventtype: 'core.user_auth.login_failed'
                    displaymessage: 'Failed login to Okta'
                condition: sel
        """
    )
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == [
        '{job=~".+"} | json | (event_eventType=~`(?i)^policy\\.lifecycle\\.update$` or '
        "event_eventType=~`(?i)^policy\\.lifecycle\\.delete$`) and "
        "event_legacyEventType=~`(?i)^core\\.user_auth\\.login_failed$` and "
        "event_displayMessage=~`(?i)^Failed\\ login\\ to\\ Okta$`"
    ]


def test_okta_json_pipeline_exclusive_exhaustive():
    pipeline = loki_okta_system_log()
    backend = LogQLBackend(processing_pipeline=pipeline)

    boilerplate = """
    title: Test
    status: test
    logsource:
        product: okta
        service: okta
    detection:
        sel:
            {fieldName}: test_value
        condition: sel
    """

    rules = [
        ("eventtype", ['{job=~".+"} | json | event_eventType=~`(?i)^test_value$`']),
        (
            "legacyeventtype",
            ['{job=~".+"} | json | event_legacyEventType=~`(?i)^test_value$`'],
        ),
        (
            "actor.alternateid",
            ['{job=~".+"} | json | event_actor_alternateId=~`(?i)^test_value$`'],
        ),
        (
            "actor.displayname",
            ['{job=~".+"} | json | event_actor_displayName=~`(?i)^test_value$`'],
        ),
        (
            "client.useragent.rawuseragent",
            [
                '{job=~".+"} | json | event_client_userAgent_rawUserAgent=~`(?i)^test_value$`'
            ],
        ),
        (
            "client.useragent.os",
            ['{job=~".+"} | json | event_client_userAgent_os=~`(?i)^test_value$`'],
        ),
        (
            "client.useragent.browser",
            ['{job=~".+"} | json | event_client_userAgent_browser=~`(?i)^test_value$`'],
        ),
        (
            "client.geographicalcontext.geolocation.lat",
            [
                '{job=~".+"} | json | event_client_geographicalContext_geolocation_lat=~`(?i)^test_'
                "value$`"
            ],
        ),
        (
            "client.geographicalcontext.geolocation.lon",
            [
                '{job=~".+"} | json | event_client_geographicalContext_geolocation_lon=~`(?i)^test_'
                "value$`"
            ],
        ),
        (
            "client.geographicalcontext.city",
            [
                '{job=~".+"} | json | event_client_geographicalContext_city=~`(?i)^test_value$`'
            ],
        ),
        (
            "client.geographicalcontext.state",
            [
                '{job=~".+"} | json | event_client_geographicalContext_state=~`(?i)^test_value$`'
            ],
        ),
        (
            "client.geographicalcontext.country",
            [
                '{job=~".+"} | json | event_client_geographicalContext_country=~`(?i)^test_value$`'
            ],
        ),
        (
            "client.geographicalcontext.postalcode",
            [
                '{job=~".+"} | json | event_client_geographicalContext_postalCode=~`(?i)^test_'
                "value$`"
            ],
        ),
        (
            "client.ipaddress",
            ['{job=~".+"} | json | event_client_ipAddress=~`(?i)^test_value$`'],
        ),
        (
            "debugcontext.debugdata.requesturi",
            [
                '{job=~".+"} | json | event_debugContext_debugData_requestUri=~`(?i)^test_value$`'
            ],
        ),
        (
            "debugcontext.debugdata.originalprincipal.id",
            [
                '{job=~".+"} | json | event_debugContext_debugData_originalPrincipal_id=~`(?i)^test'
                "_value$`"
            ],
        ),
        (
            "debugcontext.debugdata.originalprincipal.type",
            [
                '{job=~".+"} | json | event_debugContext_debugData_originalPrincipal_type=~`(?i)'
                "^test_value$`"
            ],
        ),
        (
            "debugcontext.debugdata.originalprincipal.alternateid",
            [
                '{job=~".+"} | json | event_debugContext_debugData_originalPrincipal_alternateId=~`'
                "(?i)^test_value$`"
            ],
        ),
        (
            "debugcontext.debugdata.originalprincipal.displayname",
            [
                '{job=~".+"} | json | event_debugContext_debugData_originalPrincipal_displayName=~`'
                "(?i)^test_value$`"
            ],
        ),
        (
            "debugcontext.debugdata.behaviors",
            [
                '{job=~".+"} | json | event_debugContext_debugData_behaviors=~`(?i)^test_value$`'
            ],
        ),
        (
            "debugcontext.debugdata.logonlysecuritydata",
            [
                '{job=~".+"} | json | event_debugContext_debugData_logOnlySecurityData=~`(?i)^test_'
                "value$`"
            ],
        ),
        (
            "authenticationcontext.authenticationprovider",
            [
                '{job=~".+"} | json | event_authenticationContext_authenticationProvider=~`(?i)'
                "^test_value$`"
            ],
        ),
        (
            "authenticationcontext.authenticationstep",
            [
                '{job=~".+"} | json | event_authenticationContext_authenticationStep=~`(?i)^test_'
                "value$`"
            ],
        ),
        (
            "authenticationcontext.credentialprovider",
            [
                '{job=~".+"} | json | event_authenticationContext_credentialProvider=~`(?i)^test_'
                "value$`"
            ],
        ),
        (
            "authenticationcontext.credentialtype",
            [
                '{job=~".+"} | json | event_authenticationContext_credentialType=~`(?i)^test_'
                "value$`"
            ],
        ),
        (
            "authenticationcontext.issuer.id",
            [
                '{job=~".+"} | json | event_authenticationContext_issuer_id=~`(?i)^test_value$`'
            ],
        ),
        (
            "authenticationcontext.issuer.type",
            [
                '{job=~".+"} | json | event_authenticationContext_issuer_type=~`(?i)^test_value$`'
            ],
        ),
        (
            "authenticationcontext.externalsessionid",
            [
                '{job=~".+"} | json | event_authenticationContext_externalSessionId=~`(?i)^test_'
                "value$`"
            ],
        ),
        (
            "authenticationcontext.interface",
            [
                '{job=~".+"} | json | event_authenticationContext_interface=~`(?i)^test_value$`'
            ],
        ),
        (
            "securitycontext.asnumber",
            ['{job=~".+"} | json | event_securityContext_asNumber=~`(?i)^test_value$`'],
        ),
        (
            "securitycontext.asorg",
            ['{job=~".+"} | json | event_securityContext_asOrg=~`(?i)^test_value$`'],
        ),
        (
            "securitycontext.isp",
            ['{job=~".+"} | json | event_securityContext_isp=~`(?i)^test_value$`'],
        ),
        (
            "securitycontext.domain",
            ['{job=~".+"} | json | event_securityContext_domain=~`(?i)^test_value$`'],
        ),
        (
            "securitycontext.isproxy",
            ['{job=~".+"} | json | event_securityContext_isProxy=~`(?i)^test_value$`'],
        ),
        (
            "target.alternateid",
            ['{job=~".+"} | json | event_target_alternateId=~`(?i)^test_value$`'],
        ),
        (
            "target.displayname",
            ['{job=~".+"} | json | event_target_displayName=~`(?i)^test_value$`'],
        ),
        (
            "target.detailentry",
            ['{job=~".+"} | json | event_target_detailEntry=~`(?i)^test_value$`'],
        ),
    ]

    for rule in rules:
        sigma_rule = SigmaCollection.from_yaml(boilerplate.format(fieldName=rule[0]))
        loki_rule = backend.convert(sigma_rule)
        assert loki_rule == rule[1]


def test_loki_parser_pipeline(sigma_rules: SigmaCollection):
    pipeline = ProcessingPipeline(
        name="Test custom Loki parser pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="set_loki_parser_pattern",
                transformation=SetCustomAttributeTransformation(
                    attribute=LokiCustomAttributes.PARSER.value,
                    value="pattern `<ip> <ts> <msg>`",
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    loki_rule = backend.convert(sigma_rules)
    assert loki_rule == [
        '{job=~".+"} | pattern `<ip> <ts> <msg>` | msg=~`(?i)^testing$`'
    ]


def test_loki_logsource_selection_pipeline(sigma_rules: SigmaCollection):
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="set_loki_logsource_selection",
                transformation=SetCustomAttributeTransformation(
                    attribute=LokiCustomAttributes.LOGSOURCE_SELECTION.value,
                    value="{job=`mylogs`,filename=~`.*[\\d]+.log$`}",
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    loki_rule = backend.convert(sigma_rules)
    assert loki_rule == [
        "{job=`mylogs`,filename=~`.*[\\d]+.log$`} | logfmt | msg=~`(?i)^testing$`"
    ]


def test_single_custom_log_source_pipeline(sigma_rules: SigmaCollection):
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="complex_custom_log_source",
                transformation=CustomLogSourceTransformation(
                    selection={
                        "message|fieldref": "msg",
                    },
                    template=True,
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    loki_rule = backend.convert(sigma_rules)
    assert loki_rule == ["{message=`testing`} | logfmt | msg=~`(?i)^testing$`"]


def test_simple_custom_log_source_pipeline(sigma_rules: SigmaCollection):
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="complex_custom_log_source",
                transformation=CustomLogSourceTransformation(
                    selection={
                        "job": ["a", "b", "c"],
                        "message|fieldref": "msg",
                        "env": "$product",
                    },
                    template=True,
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    loki_rule = backend.convert(sigma_rules)
    assert loki_rule == [
        "{job=~`a|b|c`,message=`testing`,env=`test`} | logfmt | msg=~`(?i)^testing$`"
    ]


def test_field_renamed_custom_log_source_pipeline(sigma_rules: SigmaCollection):
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="update_msg_field_name",
                transformation=FieldMappingTransformation(
                    mapping={
                        "msg": "message",
                    }
                ),
            ),
            ProcessingItem(
                identifier="complex_custom_log_source",
                transformation=CustomLogSourceTransformation(
                    selection={"msg_lbl|fieldref": "message"}
                ),
            ),
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    loki_rule = backend.convert(sigma_rules)
    assert loki_rule == ["{msg_lbl=`testing`} | logfmt | message=~`(?i)^testing$`"]


def test_multiple_custom_log_source_pipeline(sigma_rules: SigmaCollection):
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="complex_custom_log_source",
                transformation=CustomLogSourceTransformation(
                    selection={
                        "name|re": "okta.logs",
                        "job|contains": "secops",
                        "eventType|fieldref": "eventType",
                    },
                    template=True,
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                product: okta
                service: okta
            detection:
                sel1:
                    eventType:
                        - policy.lifecycle.update
                        - policy.lifecycle.del*
                    legacyeventtype: 'core.user_auth.login_failed'
                    displaymessage: 'Failed login to Okta'
                sel2:
                    eventType|re: 'policy\\.life.*\\.'
                condition: all of sel*
        """
    )
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == [
        "{name=~`okta.logs`,job=~`.*secops.*`,"
        "eventType=~`policy\\.life.*\\.|policy\\.lifecycle\\.update|policy\\.lifecycle\\.del.*`} "
        "| logfmt | (eventType=~`(?i)^policy\\.lifecycle\\.update$` "
        "or eventType=~`(?i)^policy\\.lifecycle\\.del.*`) "
        "and legacyeventtype=~`(?i)^core\\.user_auth\\.login_failed$` "
        "and displaymessage=~`(?i)^Failed\\ login\\ to\\ Okta$` "
        "and eventType=~`policy\\.life.*\\.`"
    ]


def test_custom_log_source_rule_with_keywords():
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="complex_custom_log_source",
                transformation=CustomLogSourceTransformation(
                    selection={
                        "job": ["a", "b", "c"],
                        "message|fieldref": "msg",
                        "env": "$product",
                    },
                    template=True,
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    sigma_rule = SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            product: okta
            service: okta
        detection:
            sel:
                eventType:
                    - policy.lifecycle.update
                    - policy.lifecycle.del*
                legacyeventtype: 'core.user_auth.login_failed'
                msg: 'Failed login to Okta'
            keywords:
                - 'policy\\.life.*\\.'
            condition: sel and keywords
        """
    )
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule[0].startswith(
        "{job=~`a|b|c`,message=`Failed login to Okta`,env=`okta`}"
    )


def test_skip_both_negated_and_positive_custom_log_source_pipeline(
    sigma_rules: SigmaCollection,
):
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="complex_custom_log_source",
                transformation=CustomLogSourceTransformation(
                    selection={
                        "name": "okta-logs",
                        "eventType|fieldref": "eventType",
                    }
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                product: okta
                service: okta
            detection:
                sel1:
                    eventType|startswith: policy.lifecycle.
                sel2:
                    eventType|endswith: create
                condition: sel1 and not sel2
        """
    )
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == [
        "{name=`okta-logs`} | logfmt | eventType=~`(?i)^policy\\.lifecycle\\..*` "
        "and eventType!~`(?i).*create$`"
    ]


def test_negated_custom_log_source_pipeline(sigma_rules: SigmaCollection):
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="complex_custom_log_source",
                transformation=CustomLogSourceTransformation(
                    selection={
                        "eventType|fieldref": "eventType",
                        "stream|fieldref": "ruleField",
                    },
                    template=True,
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                product: okta
                service: okta
            detection:
                sel1:
                    legacyeventtype: 'core.user_auth.login_failed'
                    displaymessage: 'Failed login to Okta'
                sel2:
                    eventType: 'policy.lifecycle.update'
                    ruleField|re: '.*out'
                condition: sel1 and not sel2
        """
    )
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == [
        "{eventType!=`policy.lifecycle.update`,stream!~`.*out`} "
        "| logfmt | legacyeventtype=~`(?i)^core\\.user_auth\\.login_failed$` "
        "and displaymessage=~`(?i)^Failed\\ login\\ to\\ Okta$` "
        "and (eventType!~`(?i)^policy\\.lifecycle\\.update$` "
        "or ruleField!~`.*out`)"
    ]


def test_unsupported_line_filter_custom_log_source_pipeline(
    sigma_rules: SigmaCollection,
):
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="invalid_custom_log_source",
                transformation=CustomLogSourceTransformation(
                    selection={
                        "": "value",
                    }
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    raised_error = False
    try:
        backend.convert(sigma_rules)
    except Exception as e:
        raised_error = True
        assert isinstance(e, SigmaFeatureNotSupportedByBackendError)
        assert "only supports field equals value conditions" in str(e)
    assert raised_error


def test_unsupported_nested_or_custom_log_source_pipeline(sigma_rules: SigmaCollection):
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="invalid_custom_log_source",
                transformation=CustomLogSourceTransformation(
                    selection={
                        "test|all": ["a", "b", "c"],
                    }
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    raised_error = False
    try:
        backend.convert(sigma_rules)
    except Exception as e:
        raised_error = True
        assert isinstance(e, SigmaFeatureNotSupportedByBackendError)
        assert "allows one required value for a field" in str(e)
    assert raised_error


def test_unsupported_filter_custom_log_source_pipeline(sigma_rules: SigmaCollection):
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="invalid_custom_log_source",
                transformation=CustomLogSourceTransformation(
                    selection={
                        "test|cidr": "1.2.0.0/16",
                    }
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    raised_error = False
    try:
        backend.convert(sigma_rules)
    except Exception as e:
        raised_error = True
        assert isinstance(e, SigmaFeatureNotSupportedByBackendError)
        assert (
            "only supports: string values, field references and regular expressions"
            in str(e)
        )
    assert raised_error


def test_processing_pipeline_custom_attribute_from_dict():
    pipeline_dict = {
        "name": "Testing Custom Pipeline",
        "vars": {},
        "priority": 10,
        "transformations": [
            {
                "id": "custom_pipeline_dict",
                "type": "set_custom_attribute",
                "rule_conditions": [{"type": "logsource", "category": "web"}],
                "detection_item_conditions": [
                    {"type": "match_string", "cond": "any", "pattern": "test"}
                ],
                "field_name_conditions": [
                    {"type": "include_fields", "fields": ["fieldA", "fieldB"]}
                ],
                "rule_cond_op": "or",
                "detection_item_cond_op": "or",
                "field_name_cond_op": "or",
                "rule_cond_not": True,
                "detection_item_cond_not": True,
                "field_name_cond_not": True,
                "attribute": "loki_parser",
                "value": "json",
            }
        ],
    }
    processing_pipeline = ProcessingPipeline.from_dict(pipeline_dict)
    assert processing_pipeline is not None
    assert processing_pipeline.priority == int(pipeline_dict["priority"])
    assert len(processing_pipeline.items) == len(pipeline_dict["transformations"])
    processing_item = processing_pipeline.items[0]
    assert processing_item is not None
    assert processing_item.transformation is not None
    assert isinstance(processing_item.transformation, SetCustomAttributeTransformation)
    assert (
        processing_item.transformation.attribute
        == pipeline_dict["transformations"][0]["attribute"]
    )
    assert (
        processing_item.transformation.value
        == pipeline_dict["transformations"][0]["value"]
    )


def test_set_custom_attribute_correlation_rule():
    """
    Test that the custom attribute transformation can be applied to a correlation rule.
    """
    sigma_rules = SigmaCollection.from_yaml(
        """
title: Test
name: failed_login
status: test
logsource:
    product: okta
    service: okta
detection:
    sel:
        legacyeventtype: 'core.user_auth.login_failed'
        displaymessage: 'Failed login to Okta'
    condition: sel
---
title: Valid correlation
status: test
correlation:
    type: event_count
    rules: failed_login
    group-by: actor.alternateid
    timespan: 10m
    condition:
        gte: 10
        """
    )
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="set_loki_logsource_selection",
                transformation=SetCustomAttributeTransformation(
                    attribute=LokiCustomAttributes.LOGSOURCE_SELECTION.value,
                    value="{job=`mylogs`,filename=~`.*[\\d]+.log$`}",
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    loki_rule = backend.convert(sigma_rules)
    assert len(loki_rule) == 1
    assert "job=`mylogs`" in loki_rule[0]
    assert "filename=~`.*[\d]+.log$`" in loki_rule[0]

def test_set_custom_log_source_correlation_rule():
    """
    Test that the custom attribute transformation can be applied to a correlation rule.
    """
    sigma_rules = SigmaCollection.from_yaml(
        """
title: Test
name: failed_login
status: test
logsource:
    product: okta
    service: okta
detection:
    sel:
        legacyeventtype: 'core.user_auth.login_failed'
        displaymessage: 'Failed login to Okta'
    condition: sel
---
title: Valid correlation
status: test
correlation:
    type: event_count
    rules: failed_login
    group-by: actor.alternateid
    timespan: 10m
    condition:
        gte: 10
        """
    )
    pipeline = ProcessingPipeline(
        name="Test custom Loki logsource pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="set_loki_custom_logsource_selection",
                transformation=CustomLogSourceTransformation(
                    selection={
                        "name": "okta-logs",
                        "eventType|fieldref": "legacyeventtype",
                    }
                ),
            )
        ],
    )
    backend = LogQLBackend(processing_pipeline=pipeline)
    loki_rule = backend.convert(sigma_rules)
    assert len(loki_rule) == 1
    assert loki_rule[0].startswith("sum by (actor_alternateid)")
    assert "name=`okta-logs`" in loki_rule[0]
    assert "eventType=`core.user_auth.login_failed`" in loki_rule[0]
