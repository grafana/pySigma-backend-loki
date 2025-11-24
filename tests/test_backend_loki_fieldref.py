import pytest
from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline


@pytest.fixture
def loki_backend():
    return LogQLBackend(add_line_filters=True)


# Testing line filters introduction
def test_loki_field_ref_single(loki_backend: LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|fieldref: fieldA
                condition: sel
        """
        )
    ) == [
        '{job=~".+"} | logfmt | label_format match_0=`{{ if eq .fieldA .field }}true{{ else }}false{{ end }}` | match_0=`true`'
    ]


def test_loki_field_ref_multi(loki_backend: LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|fieldref: fieldA
                    field2|fieldref: fieldB
                condition: sel
            """
        )
    ) == [
        '{job=~".+"} | logfmt | label_format match_0=`{{ if eq .fieldA .field1 }}true{{ else }}false{{ end }}`,match_1=`{{ if eq .fieldB .field2 }}true{{ else }}false{{ end }}` | match_0=`true` and match_1=`true`'
    ]


def test_loki_field_ref_json(loki_backend: LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: windows 
            detection:
                sel:
                    field|fieldref: fieldA
                condition: sel
            """
        )
    ) == [
        '{job=~"eventlog|winlog|windows|fluentbit.*"} | json | label_format match_0=`{{ if eq .fieldA .field }}true{{ else }}false{{ end }}` | match_0=`true`'
    ]


def test_loki_field_ref_json_multi_selection(loki_backend: LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: windows 
            detection:
                sel:
                    field1|fieldref: fieldA
                    field2: Something
                condition: sel
            """
        )
    ) == [
        '{job=~"eventlog|winlog|windows|fluentbit.*"}  | json | field2=~`(?i)^Something$`'
        "| label_format match_0=`{{ if eq .fieldA .field1 }}true{{ else }}false{{ end }}` "
        "| match_0=`true`"
    ]


def test_loki_field_ref_negated(loki_backend: LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: windows
            detection:
                sel:
                    field|fieldref: fieldA
                sel2:
                    field2|fieldref: fieldB
                condition: sel and not sel2
            """
        )
    ) == [
        '{job=~"eventlog|winlog|windows|fluentbit.*"} | json | label_format match_0=`{{ if eq .fieldA .field }}true{{ else }}false{{ end }}`,match_1=`{{ if eq .fieldB .field2 }}true{{ else }}false{{ end }}` | match_0=`true` and match_1!=`true`'
    ]


def test_loki_field_ref_with_pipeline(loki_backend: LogQLBackend):
    pipeline = ProcessingPipeline.from_yaml(
        """
        name: Test Pipeline
        priority: 20
        transformations:
            - id: field_prefix
              type: field_name_prefix
              prefix: "event_"
        """
    )
    loki_backend.processing_pipeline = pipeline

    assert loki_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: windows
            detection:
                sel:
                    field|fieldref: fieldA
                condition: sel
            """
        )
    ) == [
        '{job=~"eventlog|winlog|windows|fluentbit.*"} | json | label_format match_0=`{{ if eq .event_fieldA .event_field }}true{{ else }}false{{ end }}` | match_0=`true`'
    ]


def test_loki_field_ref_substring_matching(loki_backend: LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: windows
            detection:
                sel:
                    field1|fieldref|contains: fieldA
                sel2:
                    field2|fieldref|endswith: fieldB
                sel3:
                    field3|fieldref|startswith: fieldC
                condition: sel and not sel2 or sel3
            """
        )
    ) == [
        '{job=~"eventlog|winlog|windows|fluentbit.*"} | json | '
        + "label_format match_0=`{{ if contains .fieldA .field1 }}true{{ else }}false{{ end }}`,"
        + "match_1=`{{ if hasSuffix .fieldB .field2 }}true{{ else }}false{{ end }}`,"
        + "match_2=`{{ if hasPrefix .fieldC .field3 }}true{{ else }}false{{ end }}` "
        + "| match_0=`true` and match_1!=`true` and match_2=`true`"
    ]
