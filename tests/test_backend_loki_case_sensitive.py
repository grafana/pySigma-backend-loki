import pytest
import random
import string
import warnings
from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


@pytest.fixture
def loki_backend():
    return LogQLBackend(case_insensitive=False)


# Testing field filters
def test_loki_field_eq(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=`valueA`']
    )


def test_loki_field_eq_tilde(loki_backend: LogQLBackend):
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
                    fieldA: value`A
                condition: sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA="value`A"']
    )


def test_loki_field_eq_tilde_double_quote(loki_backend: LogQLBackend):
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
                    fieldA: v"alue`A
                condition: sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA="v\\"alue`A"']
    )


def test_loki_field_eq_num(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=100']
    )


# Testing boolean logic
def test_loki_and_expression(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=`valueA` and fieldB=`valueB`']
    )


def test_loki_or_expression(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=`valueA` or fieldB=`valueB`']
    )


def test_loki_and_or_expression(loki_backend: LogQLBackend):
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
            '{job=~".+"} | logfmt | (fieldA=`valueA1` or fieldA=`valueA2`) and '
            "(fieldB=`valueB1` or fieldB=`valueB2`)"
        ]
    )


def test_loki_or_and_expression(loki_backend: LogQLBackend):
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
            '{job=~".+"} | logfmt | fieldA=`valueA1` and fieldB=`valueB1` or '
            "fieldA=`valueA2` and fieldB=`valueB2`"
        ]
    )


# Loki doesn't support in expressions, so in this case, multiple or conditions should be produced
def test_loki_in_expression(loki_backend: LogQLBackend):
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
            '{job=~".+"} | logfmt | fieldA=`valueA` or fieldA=`valueB` or fieldA=`valueC`'
        ]
    )


def test_loki_all_query(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=`valueA` and fieldA=`valueB`']
    )


def test_loki_all_contains_query(loki_backend: LogQLBackend):
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
            '{job=~".+"} | logfmt | fieldA=~`(?i).*valueA.*` and fieldA=~`(?i).*valueB.*`'
        ]
    )


# Testing different search identifiers
def test_loki_null(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=``']
    )


# Loki does not support wildcards, so we use case-insensitive regular expressions instead
def test_loki_wildcard_single(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=~`(?i)va.ue`']
    )


def test_loki_wildcard_multi(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=~`(?i)value.*`']
    )


# Wildcarded searches may include other regex metacharacters -
# these need to be escaped to prevent them from being used in the transformed query
def test_loki_wildcard_escape(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=~`(?i)\\^v\\)\\+\\[al\\]u\\(e.*\\$`']
    )


def test_loki_cased_query(loki_backend: LogQLBackend):
    """Note: given we are already generating case-sensitive queries with this configuration,
    the cased modifier should have no effect"""
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
                    fieldA|cased: fooBAR
                    fieldB: fooBAR
                condition: sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA=`fooBAR` and fieldB=`fooBAR`']
    )


def test_loki_regex_query(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=~`foo.*bar` and fieldB=`foo`']
    )


def test_loki_field_re_tilde(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=~"value`A"']
    )


def test_loki_field_re_tilde_double_quote(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=~"v\\"alue`A"']
    )


def test_loki_field_startswith(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=~`(?i)foo.*`']
    )


def test_loki_field_endswith(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=~`(?i).*bar`']
    )


def test_loki_field_contains(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=~`(?i).*ooba.*`']
    )


def test_loki_cidr_query(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=ip("192.168.0.0/16")']
    )


def test_loki_base64_query(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA=`dmFsdWU=`']
    )


def test_loki_base64offset_query(loki_backend: LogQLBackend):
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
            '{job=~".+"} | logfmt | fieldA=`dmFsdW` or fieldA=`ZhbHVl` or fieldA=`2YWx1Z`'
        ]
    )


def test_loki_field_name_with_whitespace(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | field_name=`value`']
    )


def test_loki_field_name_leading_num(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | _0field=`value`']
    )


def test_loki_field_name_empty_whitespace_null(loki_backend: LogQLBackend):
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
                      "": valueA
                      ~: valueB
                      "   ": valueC
                  condition: sel
          """
            )
        )
        == ['{job=~".+"} |= `valueA` |= `valueB` | logfmt | =`valueC`']
    )


def test_loki_field_name_invalid(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | field_name_A_Z=`value`']
    )


# Testing unbound keyword line filters
def test_loki_unbound(loki_backend: LogQLBackend):
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
                condition: keywords
        """
            )
        )
        == ['{job=~".+"} |= `value`']
    )


def test_loki_unbound_num(loki_backend: LogQLBackend):
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
                    100
                condition: keywords
        """
            )
        )
        == ['{job=~".+"} |= 100']
    )


def test_loki_unbound_re_wildcard(loki_backend: LogQLBackend):
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
                    va?ue*
                condition: keywords
        """
            )
        )
        == ['{job=~".+"} |~ `(?i)va.ue`']
    )


def test_loki_unbound_strip_outer_wildcards(loki_backend: LogQLBackend):
    """
    As a line filter implicitly includes leading/trailing wildcards if there are no
    line start/end metacharacters, we can remove them from a pattern without issue.
    Note: this is also a workaround for grafana/loki#7837
    """
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
                keywordA:
                    - '*valueA*'
                keywordB:
                    - '*valueB'
                keywordC:
                    - 'valueC*'
                keywordD:
                    - '**' # this would achieve nothing in Loki - should be dropped
                condition: all of keyword*
        """
            )
        )
        == ['{job=~".+"} |~ `(?i)valueA` |~ `(?i)valueB` |~ `(?i)valueC`']
    )


def test_loki_unbound_re_strip_outer_wildcards(loki_backend: LogQLBackend):
    """
    As per test_loki_unbound_strip_outer_wildcards, but with a regex rather than using
    wildcards.
    """
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
                keywordA:
                    '|re': '.*valueA.*'
                keywordB:
                    '|re': '.*valueB'
                keywordC:
                    '|re': 'valueC.*'
                keywordD:
                    '|re': '.*.*'
                condition: all of keyword*
        """
            )
        )
        == ['{job=~".+"} |~ `valueA` |~ `valueB` |~ `valueC`']
    )


def test_loki_unbound_re_wildcard_no_strip(loki_backend: LogQLBackend):
    """
    Test that an unbound regular expression with leading/trailing wildcards and line
    start/end metacharacters does not strip the wildcards.
    """
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
                    '|re': '^.*value.*$'
                condition: keywords
        """
            )
        )
        == ['{job=~".+"} |~ `^.*value.*$`']
    )


def test_loki_unbound_re_at_least_one_no_strip(loki_backend: LogQLBackend):
    """
    Test that "at least one" wildcards are also not stripped (since line filters do
    not ensure that condition).
    """
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
                    '|re': '.+value.+'
                condition: keywords
        """
            )
        )
        == ['{job=~".+"} |~ `.+value.+`']
    )


def test_loki_and_unbound(loki_backend: LogQLBackend):
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
                condition: keyword1 and keyword2
        """
            )
        )
        == ['{job=~".+"} |= `valueA` |= `valueB`']
    )


def test_loki_or_unbound(loki_backend: LogQLBackend):
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
                condition: keywords
        """
            )
        )
        == ['{job=~".+"} |~ `valueA|valueB`']
    )


def test_loki_or_unbound_wildcard(loki_backend: LogQLBackend):
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
                    - '*valueA'
                    - 'valueB*'
                condition: keywords
        """
            )
        )
        == ['{job=~".+"} |~ `(?i).*valueA|valueB.*`']
    )


def test_loki_or_unbound_tilde_double_quote(loki_backend: LogQLBackend):
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
                    - value`A
                    - value"B
                condition: keywords
        """
            )
        )
        == ['{job=~".+"} |~ "value`A|value\\"B"']
    )


def test_loki_multi_or_unbound(loki_backend: LogQLBackend):
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
                keywordA:
                    - valueA
                    - valueB
                keywordB:
                    - valueC
                    - valueD
                condition: keywordA and keywordB
        """
            )
        )
        == ['{job=~".+"} |~ `valueA|valueB` |~ `valueC|valueD`']
    )


# Testing both field filters and unbound line filters
def test_loki_field_and_unbound(loki_backend: LogQLBackend):
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
                    valueA
                sel:
                    fieldA: valueB
                condition: keywords and sel
        """
            )
        )
        == ['{job=~".+"} |= `valueA` | logfmt | fieldA=`valueB`']
    )


def test_loki_field_and_unbound_group_expression(loki_backend: LogQLBackend):
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
                keywords1:
                    valueB
                keywords2:
                    valueC
                condition: sel and (keywords1 and keywords2)
        """
            )
        )
        == ['{job=~".+"} |= `valueB` |= `valueC` | logfmt | fieldA=`valueA`']
    )


# Testing specific logsources and other Sigma features
def test_loki_windows_logsource(loki_backend: LogQLBackend):
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
        == ['{job=~"eventlog|winlog|windows|fluentbit.*"} | json | key1_key2=`value`']
    )


def test_loki_azure_logsource(loki_backend: LogQLBackend):
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
        == ['{job="logstash"} | json | key1_key2=`value`']
    )


def test_loki_fields(loki_backend: LogQLBackend):
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
            fields:
                - fieldA
                - fieldB
        """
            )
        )
        == [
            '{job=~".+"} | logfmt | fieldA=`valueA` and fieldB=`valueB` | '
            'line_format "{{.fieldA}} {{.fieldB}}"'
        ]
    )


def test_loki_very_long_query_or(loki_backend: LogQLBackend):
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
    assert len(test) > 1 and (
        f"{long_field}=`valueA`" in q and len(q) < 5120 for q in test
    )


def test_loki_very_long_query_no_or(loki_backend: LogQLBackend):
    yaml = (
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
"""
        + "\n".join(
            "                       field"
            + "".join(random.choices(string.ascii_letters, k=5))
            + ": "
            + "".join(random.choices(string.ascii_letters, k=50))
            for _ in range(200)
        )
        + """
                condition: sel
            """
    )
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        test = loki_backend.convert(SigmaCollection.from_yaml(yaml))
        assert len(w) == 1
        assert len(test) == 1 and len(test[0]) > 5120


def test_loki_very_long_query_too_few_or_args(loki_backend: LogQLBackend):
    yaml = (
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selA:
"""
        + "\n".join(
            "                       field"
            + "".join(random.choices(string.ascii_letters, k=5))
            + ": "
            + "".join(random.choices(string.ascii_letters, k=50))
            for _ in range(100)
        )
        + """
                selB:
"""
        + "\n".join(
            "                       field"
            + "".join(random.choices(string.ascii_letters, k=5))
            + ": "
            + "".join(random.choices(string.ascii_letters, k=50))
            for _ in range(100)
        )
        + """
                condition: 1 of sel*
            """
    )
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        test = loki_backend.convert(SigmaCollection.from_yaml(yaml))
        assert len(w) == 1
        assert len(test) == 2 and all(len(query) > 5120 for query in test)


def test_loki_custom_attrs(loki_backend: LogQLBackend):
    assert (
        loki_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            logsource_loki_selection: '{job=`test`}'
            detection:
                sel:
                    fieldA: valueA
                condition: sel
            loki_parser: pattern `<ip> <ts> <msg>`
        """
            )
        )
        == ["{job=`test`} | pattern `<ip> <ts> <msg>` | fieldA=`valueA`"]
    )


# Tests for unimplemented/unsupported features
def test_loki_unbound_or_field(loki_backend: LogQLBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
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
                        valueA
                    sel:
                        fieldA: valueB
                    condition: keywords or sel
            """
            )
        )


def test_loki_collect_not_supported_errors(loki_backend: LogQLBackend):
    loki_backend.collect_errors = True
    rules = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    valueA
                sel:
                    fieldA: valueB
                condition: keywords or sel
        """
    )
    loki_backend.convert(rules)
    assert len(loki_backend.errors) == 1
    assert any(
        isinstance(e, SigmaFeatureNotSupportedByBackendError) and r == rules[0]
        for (r, e) in loki_backend.errors
    )


def test_loki_default_output(loki_backend: LogQLBackend):
    """Test for output format default."""
    # TODO: implement a test for the output format
    pass


def test_loki_ruler_output(loki_backend: LogQLBackend):
    """Test for output format ruler."""
    assert (
        loki_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: test signature
            status: test
            level: low
            description: testing
            logsource:
                category: test_category
                product: test_product
            detection:
                keyword:
                    anything
                condition: keyword
        """
            ),
            "ruler",
        )
        == """groups:
- name: Sigma rules
  rules:
  - alert: test_signature
    annotations:
      description: testing
      summary: test signature
    expr: sum(count_over_time({job=~".+"} |= `anything` [1m])) or vector(0) > 0
    labels:
      severity: low
"""
    )
