import pytest
from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


@pytest.fixture
def loki_backend():
    return LogQLBackend()


# Simple field equality test
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
        == ['{job=~".+"} | logfmt | fieldA!~`(?i)valueA`']
    )


def test_loki_field_not_eq_num(loki_backend: LogQLBackend):
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
                condition: not sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA!=100']
    )


def test_loki_field_not_not_eq(loki_backend: LogQLBackend):
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
                condition: not (not sel)
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA=~`(?i)valueA`']
    )


# Testing boolean logic
def test_loki_not_and_expression(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA!~`(?i)valueA` or fieldB!~`(?i)valueB`']
    )


def test_loki_not_or_expression(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA!~`(?i)valueA` and fieldB!~`(?i)valueB`']
    )


def test_loki_not_and_or_expression(loki_backend: LogQLBackend):
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
                condition: not sel
        """
            )
        )
        == [
            '{job=~".+"} | logfmt | fieldA!~`(?i)valueA1` and fieldA!~`(?i)valueA2` '
            "or fieldB!~`(?i)valueB1` and fieldB!~`(?i)valueB2`"
        ]
    )


def test_loki_not_or_and_expression(loki_backend: LogQLBackend):
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
                condition: not 1 of sel*
        """
            )
        )
        == [
            '{job=~".+"} | logfmt | (fieldA!~`(?i)valueA1` or fieldB!~`(?i)valueB1`) and '
            "(fieldA!~`(?i)valueA2` or fieldB!~`(?i)valueB2`)"
        ]
    )


# Loki doesn't support in expressions, so in this case, multiple or conditions should be produced
def test_loki_not_in_expression(loki_backend: LogQLBackend):
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
                condition: not sel
        """
            )
        )
        == [
            '{job=~".+"} | logfmt | fieldA!~`(?i)valueA` and fieldA!~`(?i)valueB` and '
            "fieldA!~`(?i)valueC`"
        ]
    )


def test_loki_not_all_query(loki_backend: LogQLBackend):
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
                condition: not sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA!~`(?i)valueA` or fieldA!~`(?i)valueB`']
    )


def test_loki_not_all_bracket_query(loki_backend: LogQLBackend):
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
                filter:
                    fieldB|all:
                        - valueC
                        - valueD
                condition: sel and not filter
        """
            )
        )
        == [
            '{job=~".+"} | logfmt | (fieldA=~`(?i)valueA` or fieldA=~`(?i)valueB`) and '
            "(fieldB!~`(?i)valueC` or fieldB!~`(?i)valueD`)"
        ]
    )


def test_loki_not_base64_query(loki_backend: LogQLBackend):
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
                condition: not sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA!~`(?i)dmFsdWU=`']
    )


def test_loki_not_base64offset_query(loki_backend: LogQLBackend):
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
                condition: not sel
        """
            )
        )
        == [
            '{job=~".+"} | logfmt | fieldA!~`(?i)dmFsdW` and fieldA!~`(?i)ZhbHVl` and '
            "fieldA!~`(?i)2YWx1Z`"
        ]
    )


# Testing different search identifiers
def test_loki_not_null(loki_backend: LogQLBackend):
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
                condition: not sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA!=``']
    )


# Loki does not support wildcards, so we use case-insensitive regular expressions instead
def test_loki_not_wildcard_single(loki_backend: LogQLBackend):
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
                condition: not sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA!~`(?i)va.ue`']
    )


def test_loki_not_wildcard_multi(loki_backend: LogQLBackend):
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
                condition: not sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA!~`(?i)value.*`']
    )


def test_loki_not_wildcard_unbound(loki_backend: LogQLBackend):
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
                    - va?ue*
                condition: not keywords
        """
            )
        )
        == ['{job=~".+"} !~ `(?i)va.ue`']
    )


def test_loki_not_regex_query(loki_backend: LogQLBackend):
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
                condition: not sel
        """
            )
        )
        == ['{job=~".+"} | logfmt | fieldA!~`foo.*bar` or fieldB!~`(?i)foo`']
    )


def test_loki_not_cidr_query(loki_backend: LogQLBackend):
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
        == ['{job=~".+"} | logfmt | fieldA!=ip("192.168.0.0/16")']
    )


def test_loki_not_unbound(loki_backend: LogQLBackend):
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
                condition: not keywords
        """
            )
        )
        == ['{job=~".+"} !~ `(?i)value`']
    )


def test_loki_not_unbound_num(loki_backend: LogQLBackend):
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
                condition: not keywords
        """
            )
        )
        == ['{job=~".+"} != 100']
    )


def test_loki_not_unbound_re_wildcard(loki_backend: LogQLBackend):
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
                    '|re': 'value.*'
                condition: not keywords
        """
            )
        )
        == ['{job=~".+"} !~ `value`']
    )


def test_loki_not_and_unbound(loki_backend: LogQLBackend):
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
                condition: not (keyword1 and keyword2)
        """
            )
        )
        == ['{job=~".+"} !~ `(?i)valueA|valueB`']
    )


def test_loki_not_unbound_or_field(loki_backend: LogQLBackend):
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
                condition: not (keywords or sel)
        """
            )
        )
        == ['{job=~".+"} !~ `(?i)valueA` | logfmt | fieldA!~`(?i)valueB`']
    )


def test_loki_not_unbound_and_field(loki_backend: LogQLBackend):
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
                    condition: not (keywords and sel)
            """
            )
        )


def test_loki_not_multi_or_unbound(loki_backend: LogQLBackend):
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
                    keywordA:
                        - valueA
                        - valueB
                    keywordB:
                        - valueC
                        - valueD
                    condition: not (keywordA and keywordB)
            """
            )
        )


def test_loki_not_or_unbound(loki_backend: LogQLBackend):
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
                condition: not keywords
        """
            )
        )
        == ['{job=~".+"} !~ `(?i)valueA` !~ `(?i)valueB`']
    )


def test_loki_not_unbound_wildcard(loki_backend: LogQLBackend):
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
                    value*
                condition: not keywords
        """
            )
        )
        == ['{job=~".+"} !~ `(?i)value`']
    )


def test_loki_field_and_not_multi_unbound_expression(loki_backend: LogQLBackend):
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
                keywords:
                    - valueB
                    - valueC
                condition: sel and not keywords
        """
            )
        )
        == [
            '{job=~".+"} !~ `(?i)valueB` !~ `(?i)valueC` | logfmt | fieldA=~`(?i)valueA`'
        ]
    )
