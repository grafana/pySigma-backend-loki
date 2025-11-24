from typing import Any, Dict, Tuple
import pytest
from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError, SigmaTypeError
from sigma.modifiers import modifier_mapping
from sigma.processing.pipeline import ProcessingPipeline


@pytest.fixture
def loki_backend() -> LogQLBackend:
    # Add a processing pipeline to the backend to test the expand modifier.
    pipeline = ProcessingPipeline.from_yaml(
        """
        name: Test Pipeline
        priority: 20
        vars:
            test: valueA
        transformations:
            - type: value_placeholders
        """
    )
    return LogQLBackend(processing_pipeline=pipeline)


# Mapping from modifier identifier strings to modifier classes
modifier_sample_data: Dict[str, Tuple[Any, str]] = {
    # "modifier": (value, expected_output)
    "contains": ("valueA", "fieldA=~`(?i).*valueA.*`"),
    "startswith": ("valueA", "fieldA=~`(?i)^valueA.*`"),
    "endswith": ("valueA", "fieldA=~`(?i).*valueA$`"),
    "exists": ("yes", 'fieldA!=""'),
    "base64": ("valueA", "fieldA=~`(?i)^dmFsdWVB$`"),
    "base64offset": (
        "valueA",
        "fieldA=~`(?i)^dmFsdWVB$` or fieldA=~`(?i)^ZhbHVlQ$` or fieldA=~`(?i)^2YWx1ZU$`",
    ),
    "wide": ("valueA", "fieldA=~`(?i)^v\x00a\x00l\x00u\x00e\x00A\x00$`"),
    "windash": ("-foo", "fieldA=~`(?i)^\\-foo$` or fieldA=~`(?i)^/foo$`"),
    "re": (".*valueA$", "fieldA=~`.*valueA$`"),
    "i": ("valueA", "fieldA=~`(?i)valueA`"),
    "ignorecase": ("valueA", "fieldA=~`(?i)valueA`"),
    # Multiline modifier is not supported by LogQL, and the recommended way to handle
    # multiline logs can be found below:
    # https://grafana.com/docs/loki/latest/send-data/promtail/stages/multiline/
    "m": (["valueA", "valueB"], "---"),
    "multiline": (["valueA", "valueB"], "---"),
    "s": ("valueA", "---"),
    "dotall": ("valueA", "---"),
    "cased": ("valueA", "fieldA=`valueA`"),
    "cidr": ("192.0.0.0/8", 'fieldA=ip("192.0.0.0/8")'),
    "all": (["valueA", "valueB"], "fieldA=~`(?i)^valueA$` and fieldA=~`(?i)^valueB$`"),
    "lt": (1, "fieldA<1"),
    "lte": (1, "fieldA<=1"),
    "gt": (1, "fieldA>1"),
    "gte": (1, "fieldA>=1"),
    "fieldref": (
        "fieldB",
        "label_format match_0=`{{ if eq .fieldB .fieldA }}true{{ else }}false{{ end }}`,"
        "match_1=`{{ if eq .fieldB .fieldA }}true{{ else }}false{{ end }}`"
        " | match_0=`true` and match_1!=`true`",
    ),
    "expand": ('"%test%"', "fieldA=~`(?i)^valueA$`"),
    "minute": (
        1,
        'label_format date_0=`{{ date "04" (unixToTime .fieldA) }}`,'
        'date_1=`{{ date "04" (unixToTime .fieldA) }}`'
        " | date_0=`1` and date_1!=`1`",
    ),
    "hour": (
        1,
        'label_format date_0=`{{ date "15" (unixToTime .fieldA) }}`,'
        'date_1=`{{ date "15" (unixToTime .fieldA) }}`'
        " | date_0=`1` and date_1!=`1`",
    ),
    "day": (
        1,
        'label_format date_0=`{{ date "02" (unixToTime .fieldA) }}`,'
        'date_1=`{{ date "02" (unixToTime .fieldA) }}`'
        " | date_0=`1` and date_1!=`1`",
    ),
    "week": (1, "---"),  # Unsupported by the datetime layout
    "month": (
        1,
        'label_format date_0=`{{ date "01" (unixToTime .fieldA) }}`,'
        'date_1=`{{ date "01" (unixToTime .fieldA) }}`'
        " | date_0=`1` and date_1!=`1`",
    ),
    "year": (
        1,
        'label_format date_0=`{{ date "2006" (unixToTime .fieldA) }}`,'
        'date_1=`{{ date "2006" (unixToTime .fieldA) }}`'
        " | date_0=`1` and date_1!=`1`",
    ),
}


def generate_rule_with_field_modifier(modifier: str, value: Tuple[Any, str]) -> Tuple[str, str]:
    """Generate a Sigma rule with a field modifier."""
    rule = """
    title: Test
    status: test
    logsource:
        category: test_category
        product: test_product
    detection:
        selection:
            fieldA|{modifier}: {value[0]}
        neg:
            fieldA|{modifier}: {value[0]}
        condition: selection or not neg
    """
    # Ignorecase modifier is a special case of the regex (re) modifier.
    if modifier in ["i", "ignorecase"]:
        modifier = "re|" + modifier
    return (rule.format(modifier=modifier, value=value), value[1])


def test_modifiers(loki_backend: LogQLBackend):
    # Check if all modifiers are tested.
    # This is to ensure that the test suite is updated when new modifiers are added.
    if len(modifier_sample_data) != len(modifier_mapping):
        diff = set(sorted(modifier_sample_data.keys())).symmetric_difference(
            set(sorted(modifier_mapping.keys()))
        )
        pytest.fail(
            "Not all modifiers are tested, please update the sample data: modifier_sample_data.\n"
            f"Missing modifiers: {diff}"
        )


@pytest.mark.parametrize("label", modifier_mapping.keys())
def test_loki_field_modifiers(loki_backend: LogQLBackend, label: str):
    input_rule, output_expr = generate_rule_with_field_modifier(label, modifier_sample_data[label])
    try:
        query = loki_backend.convert(SigmaCollection.from_yaml(input_rule))
        assert output_expr in query[0]
    except (SigmaFeatureNotSupportedByBackendError, SigmaTypeError):
        pytest.skip(f"Backend does not support {modifier_mapping[label].__name__} modifier")
    except Exception as e:
        pytest.fail(f"Unexpected exception: {e}")
