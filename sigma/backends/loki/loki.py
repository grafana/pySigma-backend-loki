from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression, ConditionValueExpression
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.types import SigmaCompareExpression, SigmaString, SigmaRegularExpression
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
# from sigma.pipelines.loki import # TODO: add pipeline imports or delete this line
import sigma
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Union

class LogQLBackend(TextQueryBackend):
    """Loki LogQL query backend. Generates LogQL queries as described in the Loki documentation:

    https://grafana.com/docs/loki/latest/logql/log_queries/"""
    # The backend generates grouping if required
    name : ClassVar[str] = "Loki backend"
    formats : Dict[str, str] = {
        "default": "Plain Loki queries",
        "ruler": "'ruler' output format",
    }

    # Operator precedence: tuple of Condition{AND,OR} in order of precedence.
    # LogQL lacks a NOT operator - this might be a problem for some rules
    # TODO: can we add a unary NOT operator to LogQL or can be replicate it during rule generation?
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem]] = (ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "or"
    and_token : ClassVar[str] = "and"
    eq_token : ClassVar[str] = "="  # Token inserted between field and value (without separator)

    # Rather than picking between "s and `s, defaulting to `s
    # TODO: validate the escape char and filter chars
    str_quote       : ClassVar[str] = '`'
    escape_char     : ClassVar[str] = "\\"
    add_escaped     : ClassVar[str] = "\\"
    filter_chars    : ClassVar[str] = ""

    field_quote_pattern     : ClassVar[Pattern] = re.compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")

    # LogQL does not support wildcards, so we convert them to regular expressions
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard (replaced with .*)
    wildcard_single : ClassVar[str] = "?"     # Character used as single-character wildcard (replaced with .)

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
    # TODO: can we test for (not) null fields using LogQL? Not clear (test for an empty value?)

    # TODO: these probably should be prioritised for performance reasons
    # See https://grafana.com/docs/loki/latest/logql/log_queries/#line-filter-expression
    unbound_value_str_expression : ClassVar[str] = '|= {value}'
    unbound_value_num_expression : ClassVar[str] = '|= {value}'
    unbound_value_re_expression : ClassVar[str] = '|~ `{value}`'
    # not clearly supported by Sigma?
    unbound_value_cidr_expression : ClassVar[str] = '| ip("{value}")'

    deferred_start : ClassVar[str] = "\n| "
    deferred_separator : ClassVar[str] = "\n| "

    # When converting values to regexes, we need to escape the string to prevent use of non-wildcard metacharacters
    # As str equality is case-insensitive in Sigma, but LogQL regexes are case-sensitive, we also prepend with (?i)
    def convert_wildcard_to_re(self, value: SigmaString) -> SigmaRegularExpression:
        """Convert a SigmaString value that (probably) contains wildcards into a regular expression"""
        return SigmaRegularExpression('(?i)'+re.escape(str(value)).replace('\\?', '.').replace('\\*', '.*'))

    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Overriding Sigma implementation: LogQL does not support OR'd unbounded conditions.
    # TODO: For now we will reject such queries, but we could potentially implement them with... you guessed it,
    # regexes (though I'm not so sure it's a good idea...)
    # TODO: Alternatively we could see if we can produce multiple LogQL queries from a single Sigma rule
    # TODO: If we want to consistently reject such queries, we possibly need to do a deeper search?
    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        for arg in cond.args:
            if isinstance(arg, ConditionValueExpression):
                raise SigmaFeatureNotSupportedByBackendError("Operator 'or' not supported by the backend for unbound conditions")
        else:
            return super().convert_condition_or(cond, state)

    
    # Overriding Sigma implementation: LogQL does not support wildcards - so convert them into regular expressions
    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        # Wildcards (*, ?) are special, but aren't supported in LogQL, so we switch to regex instead
        if cond.value.contains_special():
            cond.value = self.convert_wildcard_to_re(cond.value)
            return self.convert_condition_field_eq_val_re(cond, state)
        else:
            # No wildcards? No problem, we can use the default implementation
            return super().convert_condition_field_eq_val_str(cond, state)

    # As above, but for unbound queries
    def convert_condition_val_str(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        if cond.value.contains_special():
            cond.value = self.convert_wildcard_to_re(cond.value)
            return self.convert_condition_val_re(cond, state)
        else:
            return super().convert_condition_val_str(cond, state)

    # Overriding Sigma implementation - Loki has strict rules about field (label) names, so for now we will error if
    # an invalid field name is provided
    # TODO: decide should we replace invalid characters with underscores? Or should we just ensure all fields are
    # appropriately mapped?
    def escape_and_quote_field(self, field_name: str) -> str:
        if not self.field_quote_pattern.match(field_name):
            raise SigmaFeatureNotSupportedByBackendError(f"""{field_name} is not a valid Loki label.
It must start with either:
- an ASCII alphabet (A-z) character
- an underscore (_) 
- a colon (:)
It can also only contain those characters and numbers (0-9)
""")
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
    
    
