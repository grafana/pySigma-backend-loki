import pytest
from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection


@pytest.fixture
def loki_backend():
    return LogQLBackend(add_line_filters=True)


# Testing line filters introduction
def test_loki_field_ref_single(loki_backend: LogQLBackend):
    assert (
        loki_backend.convert(
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
        )
        == [
            '{job=~".+"} | logfmt | label_format match_0=`{{ if eq .field .fieldA }}true{{ else }}false{{ end }}` | match_0=`true`'
        ]
    )


def test_loki_field_ref_multi(loki_backend: LogQLBackend):
    assert (
        loki_backend.convert(
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
        )
        == [
            '{job=~".+"} | logfmt | label_format match_0=`{{ if eq .field1 .fieldA }}true{{ else }}false{{ end }}` | match_0=`true` | label_format match_1=`{{ if eq .field2 .fieldB }}true{{ else }}false{{ end }}` | match_1=`true`'
        ]
    )


def test_loki_field_ref_json(loki_backend: LogQLBackend):
    assert (
        loki_backend.convert(
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
        )
        == [
            '{job=~"eventlog|winlog|windows|fluentbit.*"} | json | label_format match_0=`{{ if eq .field .fieldA }}true{{ else }}false{{ end }}` | match_0=`true`'
        ]
    )


def test_loki_field_ref_json_multi_selection(loki_backend: LogQLBackend):
    assert (
        loki_backend.convert(
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
        )
        == [
            '{job=~"eventlog|winlog|windows|fluentbit.*"} | json | label_format match_0=`{{ if eq .field1 .fieldA }}true{{ else }}false{{ end }}` | match_0=`true` | json | field2=~`(?i)Something`'
        ]
    )
