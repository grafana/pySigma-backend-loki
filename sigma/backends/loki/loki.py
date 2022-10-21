from dataclasses import dataclass
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
from yaml import dump
from typing import ClassVar, Dict, Tuple, Pattern, List, Union

@dataclass
class LogQLDeferredUnboundExpression(DeferredQueryExpression):
    """'Defer' unbounded matching to pipelined command **BEFORE** main search expression."""
    expr : str

    def negate(self) -> DeferredQueryExpression:
        raise SigmaFeatureNotSupportedByBackendError("Negation of queries are not supported by the LogQL backend")

    def finalize_expression(self) -> str:
        return self.expr

@dataclass
class LogQLDeferredOrUnboundExpression(DeferredQueryExpression):
    """'Defer' unbounded matching to pipelined command **BEFORE** main search expression."""
    exprs : List[str]

    def negate(self) -> DeferredQueryExpression:
        raise SigmaFeatureNotSupportedByBackendError("Negation of queries are not supported by the LogQL backend")

    def finalize_expression(self) -> str:
        return f"|~ `{'|'.join((re.escape(str(val)) for val in self.exprs))}`"

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

    field_query_prefix      : ClassVar[str] = " | logfmt | "
    field_quote_pattern     : ClassVar[Pattern] = re.compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")
    field_replace_pattern   : ClassVar[Pattern] = re.compile("[^a-zA-Z0-9_:]+")
    field_null_expression   : ClassVar[str] = "{field}=``"

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

    deferred_start : ClassVar[str] = ''
    deferred_end : ClassVar[str] = ''
    deferred_separator : ClassVar[str] = ' '
    deferred_only_query : ClassVar[str] = ''

    def convert_condition_val(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> LogQLDeferredUnboundExpression:
        return LogQLDeferredUnboundExpression(state, super().convert_condition_val(cond, state))

    # When converting values to regexes, we need to escape the string to prevent use of non-wildcard metacharacters
    # As str equality is case-insensitive in Sigma, but LogQL regexes are case-sensitive, we also prepend with (?i)
    def convert_wildcard_to_re(self, value: SigmaString) -> SigmaRegularExpression:
        """Convert a SigmaString value that (probably) contains wildcards into a regular expression"""
        return SigmaRegularExpression('(?i)'+re.escape(str(value)).replace('\\?', '.').replace('\\*', '.*'))

    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Overriding Sigma implementation: LogQL does not support OR'd unbounded conditions.
    # TODO: For now we will reject such queries, but we could implement them with regexes
    # TODO: If we want to consistently reject such queries, we possibly need to do a deeper search?
    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        unbound_deferred_or = None
        for arg in cond.args:
            if isinstance(arg, ConditionValueExpression):
                if unbound_deferred_or is None:
                    unbound_deferred_or = LogQLDeferredOrUnboundExpression(state, [])
                unbound_deferred_or.exprs.append(arg.value)
            elif unbound_deferred_or is not None:
                raise SigmaFeatureNotSupportedByBackendError("Operator 'or' not supported by the backend for unbound conditions combined with field conditions", source=cond.source)
        if unbound_deferred_or is not None:
            return unbound_deferred_or
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

    # Overriding Sigma implementation - Loki has strict rules about field (label) names, so for now we will replace 
    # invalid characters with underscores
    # TODO: we should instead ensure all fields are appropriately mapped
    def escape_and_quote_field(self, field_name: str) -> str:
        if not self.field_quote_pattern.match(field_name):
            # for the time being, simply replace the disallowed characters with underscores
            field_name = "_" + self.field_replace_pattern.sub('_', field_name).strip('_')
        return field_name

    # Overriding Sigma implementing: swapping the meaning of "deferred" expressions so they appear at the start
    # of a query, rather than the end (since this is the recommended approach for LogQL)
    def finalize_query(self, rule : SigmaRule, query : Union[str, DeferredQueryExpression], index : int, state : ConversionState, output_format : str) -> Union[str, DeferredQueryExpression]:
        if isinstance(query, DeferredQueryExpression):
            query = self.deferred_only_query
        elif query is not None and len(query) > 0:
            query = self.field_query_prefix + query
        if state.has_deferred():
            query = self.deferred_separator.join((
                        deferred_expression.finalize_expression()
                        for deferred_expression in state.deferred
                    ) 
                ) + query
            # Since we've already processed the deferred parts, we can clear them
            state.deferred.clear()
        return super().finalize_query(rule, query, index, state, output_format)
    
    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        return query

    def finalize_output_default(self, queries: List[str]) -> str:
        return list(queries)
    
    def finalize_query_ruler(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Dict[str, any]:
        alert = self.field_replace_pattern.sub('_', rule.title).strip('_')
        ruler = {
            'alert': alert,
            'annotations': {
                'message': rule.title,
                'summary': rule.description
            },
            'expr': query,
            'labels': {
            }
        }
        if rule.level:
            ruler['labels']['severity'] = rule.level.name.lower()
        return ruler

    def finalize_output_ruler(self, queries: List[Dict[str, any]]) -> str:
        rules = {
            'groups': [
                {
                    'name': 'Sigma rules',
                    'rules': queries
                }
            ]
        }
        return dump(queries)
    
