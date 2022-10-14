import pytest
from sigma.exceptions import SigmaValueError, SigmaFeatureNotSupportedByBackendError
from sigma.collection import SigmaCollection
from sigma.backends.loki import LogQLBackend

@pytest.fixture
def loki_backend():
    return LogQLBackend()

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
    ) == ['fieldA=`valueA` and fieldB=`valueB`']

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
    ) == ['fieldA=`valueA` or fieldB=`valueB`']

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
    ) == ['(fieldA=`valueA1` or fieldA=`valueA2`) and (fieldB=`valueB1` or fieldB=`valueB2`)']

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
    ) == ['fieldA=`valueA1` and fieldB=`valueB1` or fieldA=`valueA2` and fieldB=`valueB2`']

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
                    fieldA: va?ue?
                condition: sel
        """)
    ) == ['fieldA=~`(?i)va.ue.`']

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
    ) == ['fieldA=~`(?i)value.*`']

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
    ) == ['fieldA=~`(?i)\\\\^v\\\\+\\\\[al\\\\]ue.*\\\\$`']

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
    ) == ['fieldA=`valueA` or fieldA=`valueB` or fieldA=`valueC`']

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
    ) == ['fieldA=~`foo.*bar` and fieldB=`foo`']

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
    ) == ['fieldA=~`(?i)foo.*`']

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
    ) == ['fieldA=~`(?i).*bar`']

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
    ) == ['fieldA=~`(?i).*ooba.*`']

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
    ) == ['field=ip("192.168.0.0/16")']

def test_loki_field_name_with_whitespace(loki_backend : LogQLBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError) as e_info:
        test = loki_backend.convert(
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
        )

def test_loki_default_output(loki_backend : LogQLBackend):
    """Test for output format default."""
    # TODO: implement a test for the output format
    pass

def test_loki_ruler_output(loki_backend : LogQLBackend):
    """Test for output format ruler."""
    # TODO: implement a test for the output format
    pass


