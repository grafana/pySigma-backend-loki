import pytest
from sigma.exceptions import SigmaValueError, SigmaFeatureNotSupportedByBackendError
from sigma.collection import SigmaCollection
from sigma.backends.loki import LogQLBackend

@pytest.fixture
def loki_backend():
    return LogQLBackend()

# Testing boolean logic
def test_loki_and_expression(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == [' | logfmt | fieldA=`valueA` and fieldB=`valueB`']

def test_loki_or_expression(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == [' | logfmt | fieldA=`valueA` or fieldB=`valueB`']

def test_loki_and_or_expression(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == [' | logfmt | (fieldA=`valueA1` or fieldA=`valueA2`) and (fieldB=`valueB1` or fieldB=`valueB2`)']

def test_loki_or_and_expression(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == [' | logfmt | fieldA=`valueA1` and fieldB=`valueB1` or fieldA=`valueA2` and fieldB=`valueB2`']

# Loki doesn't support in expressions, so in this case, multiple or conditions should be produced
def test_loki_in_expression(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == [' | logfmt | fieldA=`valueA` or fieldA=`valueB` or fieldA=`valueC`']

def test_loki_all_query(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|all:
                        - valueA
                        - valueB
                condition: sel
        """)
    ) == [' | logfmt | field=`valueA` and field=`valueB`']

def test_loki_all_contains_query(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|all|contains:
                        - valueA
                        - valueB
                condition: sel
        """)
    ) == [' | logfmt | field=~`(?i).*valueA.*` and field=~`(?i).*valueB.*`']

# Testing different search identifiers
def test_loki_null(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: null
                condition: sel
        """)
    ) == [' | logfmt | fieldA=``']

# Loki does not support wildcards, so we use case-insensitive regular expressions instead
def test_loki_wildcard_single(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: va?ue
                condition: sel
        """)
    ) == [' | logfmt | fieldA=~`(?i)va.ue`']

def test_loki_wildcard_multi(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value*
                condition: sel
        """)
    ) == [' | logfmt | fieldA=~`(?i)value.*`']

# Wildcarded searches may include other regex metacharacters - these need to be escaped to prevent them from being
# used in the transformed query
def test_loki_wildcard_escape(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: ^v+[al]ue*$
                condition: sel
        """)
    ) == [' | logfmt | fieldA=~`(?i)\\\\^v\\\\+\\\\[al\\\\]ue.*\\\\$`']

def test_loki_wildcard_unbound(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - va?ue*
                condition: keywords
        """)
    ) == ['|~ `(?i)va.ue.*`']

def test_loki_regex_query(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == [' | logfmt | fieldA=~`foo.*bar` and fieldB=`foo`']

def test_loki_field_startswith(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: foo
                condition: sel
        """)
    ) == [' | logfmt | fieldA=~`(?i)foo.*`']

def test_loki_field_endswith(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: bar
                condition: sel
        """)
    ) == [' | logfmt | fieldA=~`(?i).*bar`']

def test_loki_field_contains(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: ooba
                condition: sel
        """)
    ) == [' | logfmt | fieldA=~`(?i).*ooba.*`']

def test_loki_cidr_query(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == [' | logfmt | field=ip("192.168.0.0/16")']

def test_loki_base64_query(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|base64: value
                condition: sel
        """)
    ) == [' | logfmt | field=`dmFsdWU=`']

def test_loki_field_name_with_whitespace(loki_backend : LogQLBackend):
      assert loki_backend.convert(
          SigmaCollection.from_yaml("""
              title: Test
              status: test
              logsource:
                  category: test_category
                  product: test_product
              detection:
                  sel:
                      field name: value
                  condition: sel
          """)
      ) == [' | logfmt | _field_name=`value`']


def test_loki_unbound(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    value
                condition: keywords
        """)
    ) == ['|= `value`']

def test_loki_unbound_re_wildcard(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    value*
                condition: keywords
        """)
    ) == ['|~ `(?i)value.*`']

def test_loki_and_unbound(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['|= `valueA` |= `valueB`']

def test_loki_unbound_and_field(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    valueA
                sel:
                    field: valueB
                condition: keywords and sel
        """)
    ) == ['|= `valueA` | logfmt | field=`valueB`']

def test_loki_or_unbound_works(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['|~ `valueA|valueB`']

def test_loki_multi_or_unbound(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['|~ `valueA|valueB` |~ `valueC|valueD`']

def test_loki_unbound_or_field(loki_backend : LogQLBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError) as e_info:
        test = loki_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    keywords:
                        valueA
                    sel:
                        field: valueB
                    condition: keywords or sel
            """)
        )

def test_loki_not_unbound(loki_backend : LogQLBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError) as e_info:
        test = loki_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    keywords:
                        valueA
                    condition: not keywords
            """)
        )

def test_loki_default_output(loki_backend : LogQLBackend):
    """Test for output format default."""
    # TODO: implement a test for the output format
    pass

def test_loki_ruler_output(loki_backend : LogQLBackend):
    """Test for output format ruler."""
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
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
        """), "ruler"
    ) == """- alert: test_signature
  annotations:
    message: test signature
    summary: testing
  expr: '|= `anything`'
  labels:
    severity: low
"""

