from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression, SigmaString
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
# from sigma.pipelines.loki import # TODO: add pipeline imports or delete this line
import sigma
import re
from typing import ClassVar, Dict, Tuple, Pattern, List

class LogQLBackend(TextQueryBackend):
    """Loki LogQL query backend. Generates LogQL queries as described in the Loki documentation:

    https://grafana.com/docs/loki/latest/logql/log_queries/"""
    # The backend generates grouping if required
    name : ClassVar[str] = "Loki backend"
    formats : Dict[str, str] = {
        "default": "Plain Loki queries",
        "ruler": "'ruler' output format",
    }

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem]] = (ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "or"
    and_token : ClassVar[str] = "and"
    eq_token : ClassVar[str] = "="  # Token inserted between field and value (without separator)

    # Rather than picking between "s and `s, defaulting to `s
    str_quote       : ClassVar[str] = '`'
    escape_char     : ClassVar[str] = "\\"
    add_escaped     : ClassVar[str] = "\\"
    filter_chars    : ClassVar[str] = ""

    field_quote_pattern     : ClassVar[Pattern] = re.compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")

    # Regular expressions
    re_expression : ClassVar[str] = "{field}=~`{regex}`"
    re_escape_char : ClassVar[str] = "\\"
    re_escape : ClassVar[Tuple[str]] = ()

    # cidr expressions
    cidr_expression : ClassVar[str] = 'field=ip("{value}")'

    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    unbound_value_str_expression : ClassVar[str] = '|= {value}'
    unbound_value_num_expression : ClassVar[str] = '|= {value}'
    unbound_value_re_expression : ClassVar[str] = '|~ {value}'
    # not clearly supported by Sigma
    unbound_value_cidr_expression : ClassVar[str] = '| ip("{value}")'

    deferred_start : ClassVar[str] = "\n| "
    deferred_separator : ClassVar[str] = "\n| "

    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def escape_and_quote_field(self, field_name: str) -> str:
        if not self.field_quote_pattern.match(field_name):
            raise SigmaFeatureNotSupportedByBackendError(f"Loki fields must start with an ASCII alphabet (A-z) character, underscore (_) or colon (:), and can only contain those characters and numbers (0-9). The field `{field_name}` did not meet this requirement")
        return field_name
    
    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        # TODO: implement the per-query output for the output format default here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        return query

    def finalize_output_default(self, queries: List[str]) -> str:
        # TODO: implement the output finalization for all generated queries for the format default here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        return list(queries)
    
    def finalize_query_ruler(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        # TODO: implement the per-query output for the output format ruler here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        return query

    def finalize_output_ruler(self, queries: List[str]) -> str:
        # TODO: implement the output finalization for all generated queries for the format ruler here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        return "\n".join(queries)
    
    
