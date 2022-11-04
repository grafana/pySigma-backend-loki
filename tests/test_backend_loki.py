import pytest
from sigma.exceptions import SigmaValueError, SigmaFeatureNotSupportedByBackendError
from sigma.collection import SigmaCollection
from sigma.backends.loki import LogQLBackend

@pytest.fixture
def loki_backend():
    return LogQLBackend()

# Simple field equality test
def test_loki_field_eq(loki_backend : LogQLBackend):
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
                condition: sel
        """)
    ) == ['{job=~".*"} | logfmt | fieldA=`valueA`']

def test_loki_field_eq_num(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: 100
                condition: sel
        """)
    ) == ['{job=~".*"} | logfmt | fieldA=100']

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
    ) == ['{job=~".*"} | logfmt | fieldA=`valueA` and fieldB=`valueB`']

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
    ) == ['{job=~".*"} | logfmt | fieldA=`valueA` or fieldB=`valueB`']

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
    ) == ['{job=~".*"} | logfmt | (fieldA=`valueA1` or fieldA=`valueA2`) and (fieldB=`valueB1` or fieldB=`valueB2`)']

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
    ) == ['{job=~".*"} | logfmt | fieldA=`valueA1` and fieldB=`valueB1` or fieldA=`valueA2` and fieldB=`valueB2`']

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
    ) == ['{job=~".*"} | logfmt | fieldA=`valueA` or fieldA=`valueB` or fieldA=`valueC`']

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
                    fieldA|all:
                        - valueA
                        - valueB
                condition: sel
        """)
    ) == ['{job=~".*"} | logfmt | fieldA=`valueA` and fieldA=`valueB`']

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
                    fieldA|all|contains:
                        - valueA
                        - valueB
                condition: sel
        """)
    ) == ['{job=~".*"} | logfmt | fieldA=~`(?i).*valueA.*` and fieldA=~`(?i).*valueB.*`']

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
    ) == ['{job=~".*"} | logfmt | fieldA=``']

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
    ) == ['{job=~".*"} | logfmt | fieldA=~`(?i)va.ue`']

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
    ) == ['{job=~".*"} | logfmt | fieldA=~`(?i)value.*`']

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
    ) == ['{job=~".*"} | logfmt | fieldA=~`(?i)\\\\^v\\\\+\\\\[al\\\\]ue.*\\\\$`']

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
    ) == ['{job=~".*"} |~ `(?i)va.ue.*`']

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
    ) == ['{job=~".*"} | logfmt | fieldA=~`foo.*bar` and fieldB=`foo`']

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
    ) == ['{job=~".*"} | logfmt | fieldA=~`(?i)foo.*`']

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
    ) == ['{job=~".*"} | logfmt | fieldA=~`(?i).*bar`']

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
    ) == ['{job=~".*"} | logfmt | fieldA=~`(?i).*ooba.*`']

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
                    fieldA|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['{job=~".*"} | logfmt | fieldA=ip("192.168.0.0/16")']

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
                    fieldA|base64: value
                condition: sel
        """)
    ) == ['{job=~".*"} | logfmt | fieldA=`dmFsdWU=`']

def test_loki_base64offset_query(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|base64offset: value
                condition: sel
        """)
    ) == ['{job=~".*"} | logfmt | fieldA=`dmFsdW` or fieldA=`ZhbHVl` or fieldA=`2YWx1Z`']

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
      ) == ['{job=~".*"} | logfmt | field_name=`value`']

def test_loki_field_name_leading_num(loki_backend : LogQLBackend):
      assert loki_backend.convert(
          SigmaCollection.from_yaml("""
              title: Test
              status: test
              logsource:
                  category: test_category
                  product: test_product
              detection:
                  sel:
                      0field: value
                  condition: sel
          """)
      ) == ['{job=~".*"} | logfmt | _0field=`value`']

def test_loki_field_name_invalid(loki_backend : LogQLBackend):
      assert loki_backend.convert(
          SigmaCollection.from_yaml("""
              title: Test
              status: test
              logsource:
                  category: test_category
                  product: test_product
              detection:
                  sel:
                      field.name@A-Z: value
                  condition: sel
          """)
      ) == ['{job=~".*"} | logfmt | field_name_A_Z=`value`']

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
    ) == ['{job=~".*"} |= `value`']

def test_loki_unbound_num(loki_backend : LogQLBackend):
    assert loki_backend.convert(
        SigmaCollection.from_yaml("""
            title: test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    100
                condition: keywords
        """)
    ) == ['{job=~".*"} |= 100']

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
    ) == ['{job=~".*"} |~ `(?i)value.*`']

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
    ) == ['{job=~".*"} |= `valueA` |= `valueB`']

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
                    fieldA: valueB
                condition: keywords and sel
        """)
    ) == ['{job=~".*"} |= `valueA` | logfmt | fieldA=`valueB`']

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
    ) == ['{job=~".*"} |~ `valueA|valueB`']

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
    ) == ['{job=~".*"} |~ `valueA|valueB` |~ `valueC|valueD`']

def test_loki_windows_logsource(loki_backend : LogQLBackend):
      assert loki_backend.convert(
          SigmaCollection.from_yaml("""
              title: Test
              status: test
              logsource:
                  category: test_category
                  product: windows
              detection:
                  sel:
                      key1.key2: value
                  condition: sel
          """)
      ) == ['{job=~"eventlog|winlog|windows|fluentbit.*"} | json | key1_key2=`value`']

def test_loki_azure_logsource(loki_backend : LogQLBackend):
      assert loki_backend.convert(
          SigmaCollection.from_yaml("""
              title: Test
              status: test
              logsource:
                  category: test_category
                  product: azure
              detection:
                  sel:
                      key1.key2: value
                  condition: sel
          """)
      ) == ['{job="logstash"} | json | key1_key2=`value`']

# Unimplemented tests
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
                        fieldA: valueB
                    condition: keywords or sel
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
  expr: '{job=~".*"} |= `anything`'
  labels:
    severity: low
"""

