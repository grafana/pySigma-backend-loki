from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection
from sigma.processing.transformations import transformations
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.loki import (
    LokiCustomAttributes,
    SetCustomAttributeTransformation,
    loki_grafana_logfmt,
    loki_promtail_sysmon_message,
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
        '{job=~".+"} | logfmt | (path=`/a/path/to/something` or path=`/a/different/path`)'
        " and status=200"
    ]


def test_windows_grafana_pipeline():
    pipeline = loki_promtail_sysmon_message()
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
        "| logfmt | Image=~`(?i).*\\.exe` and event_id=1"
    ]


def test_loki_parser_pipeline():
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
    sigma_rule = SigmaCollection.from_yaml(
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
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == ['{job=~".+"} | pattern `<ip> <ts> <msg>` | msg=`testing`']


def test_loki_logsource_selection_pipeline():
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
    sigma_rule = SigmaCollection.from_yaml(
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
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == [
        "{job=`mylogs`,filename=~`.*[\\d]+.log$`} | logfmt | msg=`testing`"
    ]
