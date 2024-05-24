from typing import Any, Dict
import pytest
from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError, SigmaTypeError
from sigma.modifiers import modifier_mapping


@pytest.fixture
def loki_backend() -> LogQLBackend:
    return LogQLBackend()


# Mapping from modifier identifier strings to modifier classes
modifier_sample_data: Dict[str, Any] = {
    "contains": "valueA",
    "startswith": "valueA",
    "endswith": "valueA",
    "exists": "yes",
    "base64": "valueA",
    "base64offset": "valueA",
    "wide": "valueA",
    "windash": "-foo",
    "re": ".*valueA$",
    "i": "valueA",
    "ignorecase": "valueA",
    "m": ["valueA", "valueB"],
    "multiline": ["valueA", "valueB"],
    "s": "valueA",
    "dotall": "valueA",
    "cased": "valueA",
    "cidr": "192.0.0.0/8",
    "all": ["valueA", "valueB"],
    "lt": 1,
    "lte": 1,
    "gt": 1,
    "gte": 1,
    "fieldref": "fieldA",
    "expand": '"%test%"',
}


def generate_rule_with_field_modifier(modifier: str, value: str) -> str:
    """Generate a Sigma rule with a field modifier."""
    rule = """
    title: Test
    status: test
    logsource:
        category: test_category
        product: test_product
    detection:
        selection:
            fieldA|{modifier}: {value}
        condition: selection
    """
    return rule.format(modifier=modifier, value=value)


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
    rule = generate_rule_with_field_modifier(label, modifier_sample_data[label])
    try:
        loki_backend.convert(SigmaCollection.from_yaml(rule))
    except (SigmaFeatureNotSupportedByBackendError, SigmaTypeError):
        pytest.skip(
            f"Backend does not support {modifier_mapping[label].__name__} modifier"
        )
    except Exception as e:
        pytest.fail(f"Unexpected exception: {e}")
