import pytest
import random
import re
import string
from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection

# from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


@pytest.fixture
def loki_backend():
    return LogQLBackend(add_line_filters=True)


# Testing line filters introduction
def test_loki_lf_field_eq(loki_backend: LogQLBackend):
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
                    fieldA: valueA
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |~ `(?i)valueA` | logfmt | fieldA=~`(?i)^valueA$`']
    )


def test_loki_field_not_eq(loki_backend: LogQLBackend):
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
                    fieldA: valueA
                condition: not sel
        """
            )
        )
        == ['{job=~".+"} !~ `(?i)valueA` | logfmt | fieldA!~`(?i)^valueA$`']
    )


def test_loki_lf_field_eq_wildcard(loki_backend: LogQLBackend):
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
                    fieldA: value?A
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |~ `(?i)value.A` | logfmt | fieldA=~`(?i)^value.A$`']
    )


def test_loki_lf_field_not_eq_wildcard(loki_backend: LogQLBackend):
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
                    fieldA: value?A
                condition: not sel
        """
            )
        )
        == ['{job=~".+"} !~ `(?i)value.A` | logfmt | fieldA!~`(?i)^value.A$`']
    )


def test_loki_lf_field_eq_num(loki_backend: LogQLBackend):
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
                    fieldA: 100
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |= `fieldA=100` | logfmt | fieldA=100']
    )


# Testing boolean logic
def test_loki_lf_and_expression(loki_backend: LogQLBackend):
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
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == [
            '{job=~".+"} |~ `(?i)valueA` | logfmt | fieldA=~`(?i)^valueA$` '
            "and fieldB=~`(?i)^valueB$`"
        ]
    )


# Must not introduce partial negations, since it would exclude valid log entries
# such as: fieldA=good fieldB=good fieldC=value
def test_loki_lf_not_and_expression(loki_backend: LogQLBackend):
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
                    fieldA: valueA
                    fieldB: valueB
                condition: not sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA!~`(?i)^valueA$` or fieldB!~`(?i)^valueB$`']
    )


def test_loki_lf_or_expression(loki_backend: LogQLBackend):
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
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` or fieldB=~`(?i)^valueB$`']
    )


def test_loki_lf_not_or_expression(loki_backend: LogQLBackend):
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
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: not 1 of sel*
        """
            )
        )
        == [
            '{job=~".+"} !~ `(?i)valueA` | logfmt | fieldA!~`(?i)^valueA$` and '
            "fieldB!~`(?i)^valueB$`"
        ]
    )


def test_loki_lf_or_no_filter_expression(loki_backend: LogQLBackend):
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
                sel1:
                    aaaa: bbbb
                sel2:
                    cccc: dddd
                condition: 1 of sel*
        """
            )
        )
        == [
            '{job=~"eventlog|winlog|windows|fluentbit.*"} | json | aaaa=~`(?i)^bbbb$` '
            "or cccc=~`(?i)^dddd$`"
        ]
    )


def test_loki_lf_and_or_expression(loki_backend: LogQLBackend):
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
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
            )
        )
        == [
            '{job=~".+"} | logfmt | (fieldA=~`(?i)^valueA1$` or fieldA=~`(?i)^valueA2$`) and '
            "(fieldB=~`(?i)^valueB1$` or fieldB=~`(?i)^valueB2$`)"
        ]
    )


def test_loki_lf_or_and_expression(loki_backend: LogQLBackend):
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
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
            )
        )
        == [
            '{job=~".+"} | logfmt | fieldA=~`(?i)^valueA1$` and fieldB=~`(?i)^valueB1$` or '
            "fieldA=~`(?i)^valueA2$` and fieldB=~`(?i)^valueB2$`"
        ]
    )


# Loki doesn't support in expressions, so in this case, multiple or conditions should be produced
def test_loki_lf_in_expression(loki_backend: LogQLBackend):
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
                    fieldA:
                        - valueA
                        - valueB
                        - valueC
                condition: sel
        """
            )
        )
        == [
            '{job=~".+"} | logfmt | fieldA=~`(?i)^valueA$` or fieldA=~`(?i)^valueB$` '
            "or fieldA=~`(?i)^valueC$`"
        ]
    )


def test_loki_lf_all_query(loki_backend: LogQLBackend):
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
                    fieldA|all:
                        - valueA
                        - valueB
                condition: sel
        """
            )
        )
        == [
            '{job=~".+"} |~ `(?i)valueA` | logfmt | fieldA=~`(?i)^valueA$` and '
            "fieldA=~`(?i)^valueB$`"
        ]
    )


def test_loki_lf_all_contains_query(loki_backend: LogQLBackend):
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
                    fieldA|all|contains:
                        - valueA
                        - valueB
                condition: sel
        """
            )
        )
        == [
            '{job=~".+"} |~ `(?i).*valueA.*` | logfmt | fieldA=~`(?i).*valueA.*` '
            "and fieldA=~`(?i).*valueB.*`"
        ]
    )


# Testing different search identifiers
def test_loki_lf_null(loki_backend: LogQLBackend):
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
                    fieldA: null
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |= `fieldA=` | logfmt | fieldA=``']
    )


# Loki does not support wildcards, so we use case-insensitive regular expressions instead
def test_loki_lf_wildcard_single(loki_backend: LogQLBackend):
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
                    fieldA: va?ue
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |~ `(?i)va.ue` | logfmt | fieldA=~`(?i)^va.ue$`']
    )


def test_loki_lf_wildcard_multi(loki_backend: LogQLBackend):
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
                    fieldA: value*
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |~ `(?i)value.*` | logfmt | fieldA=~`(?i)^value.*`']
    )


# Wildcarded searches may include other regex metacharacters -
# these need to be escaped to prevent them from being used in the transformed query
def test_loki_lf_wildcard_escape(loki_backend: LogQLBackend):
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
                    fieldA: ^v)+[al]u(e*$
                condition: sel
        """
            )
        )
        == [
            '{job=~".+"} |~ `(?i)\\^v\\)\\+\\[al\\]u\\(e.*\\$` | logfmt | '
            "fieldA=~`(?i)^\\^v\\)\\+\\[al\\]u\\(e.*\\$$`"
        ]
    )


def test_loki_lf_regex_query(loki_backend: LogQLBackend):
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
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """
            )
        )
        == [
            '{job=~".+"} |~ `foo.*bar` | logfmt | fieldA=~`foo.*bar` and fieldB=~`(?i)^foo$`'
        ]
    )


def test_loki_lf_field_re_tilde(loki_backend: LogQLBackend):
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
                    fieldA|re: value`A
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |~ "value`A" | logfmt | fieldA=~"value`A"']
    )


def test_loki_lf_field_re_tilde_double_quote(loki_backend: LogQLBackend):
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
                    fieldA|re: v"alue`A
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |~ "v\\"alue`A" | logfmt | fieldA=~"v\\"alue`A"']
    )


def test_loki_lf_field_startswith(loki_backend: LogQLBackend):
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
                    fieldA|startswith: foo
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |~ `(?i)foo.*` | logfmt | fieldA=~`(?i)^foo.*`']
    )


def test_loki_lf_field_endswith(loki_backend: LogQLBackend):
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
                    fieldA|endswith: bar
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |~ `(?i).*bar` | logfmt | fieldA=~`(?i).*bar$`']
    )


def test_loki_lf_field_contains(loki_backend: LogQLBackend):
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
                    fieldA|contains: ooba
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |~ `(?i).*ooba.*` | logfmt | fieldA=~`(?i).*ooba.*`']
    )


def test_loki_lf_cidr_query(loki_backend: LogQLBackend):
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
                    fieldA|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == [
            '{job=~".+"} |= ip("192.168.0.0/16") | logfmt | fieldA=ip("192.168.0.0/16")'
        ]
    )


def test_loki_lf_not_cidr_query(loki_backend: LogQLBackend):
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
                    fieldA|cidr: 192.168.0.0/16
                condition: not sel
        """
            )
        )
        == [
            '{job=~".+"} != ip("192.168.0.0/16") | logfmt | fieldA!=ip("192.168.0.0/16")'
        ]
    )


def test_loki_lf_base64_query(loki_backend: LogQLBackend):
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
                    fieldA|base64: value
                condition: sel
        """
            )
        )
        == ['{job=~".+"} |~ `(?i)dmFsdWU=` | logfmt | fieldA=~`(?i)^dmFsdWU=$`']
    )


def test_loki_lf_base64offset_query(loki_backend: LogQLBackend):
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
                    fieldA|base64offset: value
                condition: sel
        """
            )
        )
        == [
            '{job=~".+"} | logfmt | fieldA=~`(?i)^dmFsdW$` or fieldA=~`(?i)^ZhbHVl$` or '
            "fieldA=~`(?i)^2YWx1Z$`"
        ]
    )


def test_loki_lf_field_name_with_whitespace(loki_backend: LogQLBackend):
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
                      field name: value
                  condition: sel
          """
            )
        )
        == ['{job=~".+"} |~ `(?i)value` | logfmt | field_name=~`(?i)^value$`']
    )


def test_loki_lf_field_name_leading_num(loki_backend: LogQLBackend):
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
                      0field: value
                  condition: sel
          """
            )
        )
        == ['{job=~".+"} |~ `(?i)value` | logfmt | _0field=~`(?i)^value$`']
    )


def test_loki_lf_field_name_invalid(loki_backend: LogQLBackend):
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
                      field.name@A-Z: value
                  condition: sel
          """
            )
        )
        == ['{job=~".+"} |~ `(?i)value` | logfmt | field_name_A_Z=~`(?i)^value$`']
    )


# Ensure existing line filters prevent addition of new ones
def test_loki_lf_unbound(loki_backend: LogQLBackend):
    assert (
        loki_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    value
                sel:
                    fieldA: valueA
                condition: keywords and sel
        """
            )
        )
        == ['{job=~".+"} |~ `(?i)value` | logfmt | fieldA=~`(?i)^valueA$`']
    )


def test_loki_lf_and_unbound(loki_backend: LogQLBackend):
    assert (
        loki_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keyword1:
                    valueA
                keyword2:
                    valueB
                sel:
                    fieldA: valueA
                condition: keyword1 and keyword2 and sel
        """
            )
        )
        == [
            '{job=~".+"} |~ `(?i)valueA` |~ `(?i)valueB` | logfmt | fieldA=~`(?i)^valueA$`'
        ]
    )


def test_loki_lf_or_unbound(loki_backend: LogQLBackend):
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
                keywords:
                    - valueA
                    - valueB
                sel:
                    fieldA: valueA
                condition: keywords and sel
        """
            )
        )
        == ['{job=~".+"} |~ `(?i)valueA|valueB` | logfmt | fieldA=~`(?i)^valueA$`']
    )


# Testing specific logsources and other Sigma features
def test_loki_lf_windows_logsource(loki_backend: LogQLBackend):
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
                      key1.key2: value
                  condition: sel
          """
            )
        )
        == [
            '{job=~"eventlog|winlog|windows|fluentbit.*"} |~ `(?i)value` | json | '
            "key1_key2=~`(?i)^value$`"
        ]
    )


def test_loki_lf_azure_logsource(loki_backend: LogQLBackend):
    assert (
        loki_backend.convert(
            SigmaCollection.from_yaml(
                """
              title: Test
              status: test
              logsource:
                  category: test_category
                  product: azure
              detection:
                  sel:
                      key1.key2: value
                  condition: sel
          """
            )
        )
        == ['{job="logstash"} |~ `(?i)value` | json | key1_key2=~`(?i)^value$`']
    )


def test_loki_lf_very_long_query_or(loki_backend: LogQLBackend):
    long_field = f"longField{'A' * 50}"
    yaml = (
        f"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel_each:
                    {long_field}: valueA
                sel_partitioned:
                    longFieldB|contains:
"""
        + "\n".join(
            "                       - "
            + "".join(random.choices(string.ascii_letters, k=50))
            for _ in range(100)
        )
        + """
                condition: all of sel_*
            """
    )
    test = loki_backend.convert(SigmaCollection.from_yaml(yaml))
    assert (
        len(test) > 1
        and all(
            "|~ `(?i)valueA` |" in q and f"{long_field}=~`(?i)^valueA$`" in q
            for q in test
        )
        and all(len(q) < 5120 for q in test)
    )


def test_loki_lf_very_long_query_or_right_filters(loki_backend: LogQLBackend):
    yaml = f"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel_A:
                    fieldA: value{'A'*4000}
                sel_B:
                    fieldB: value{'B'*4000}
                condition: 1 of sel_*
            """
    test = loki_backend.convert(SigmaCollection.from_yaml(yaml))
    assert len(test) > 1 and all(
        re.match(
            "|= `field([AB])=value\1{4000}` | .* | field\1=~`(\\?i)value\1{4000}`", q
        )
        for q in test
    )
