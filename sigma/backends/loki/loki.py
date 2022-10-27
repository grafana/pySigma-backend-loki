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
    value : str
    op    : str = "|=" # default to matching

    def negate(self) -> DeferredQueryExpression:
        self.op = LogQLBackend.negated_line_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        return f"{self.op} {self.value}"

@dataclass
class LogQLDeferredOrUnboundExpression(DeferredQueryExpression):
    """'Defer' unbounded OR matching to pipelined command **BEFORE** main search expression."""
    exprs : List[str]
    op    : str = "|~" # default to matching

    def negate(self) -> DeferredQueryExpression:
        self.op = LogQLBackend.negated_line_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        return f"{self.op} `{'|'.join((re.escape(str(val)) for val in self.exprs))}`"

class LogQLBackend(TextQueryBackend):
    """Loki LogQL query backend. Generates LogQL queries as described in the Loki documentation:

    https://grafana.com/docs/loki/latest/logql/log_queries/"""
    # The backend generates grouping if required
    name : ClassVar[str] = "Loki backend"
    formats : Dict[str, str] = {
        "default": "Plain Loki queries",
        "ruler": "'ruler' output format",
    }

    negated_line_filter_operator : ClassVar[Dict[str, str]] = {
        "|=": "!=",
        "!=": "|=",
        "|~": "!~",
        "!~": "|~"
    }

    negated_label_filter_operator : ClassVar[Dict[str, str]] = {
        "=" : "!=",
        "!=": "="
    }

    negated_cmp_operator : ClassVar[Dict[SigmaCompareExpression.CompareOperators, SigmaCompareExpression.CompareOperators]] = {
        SigmaCompareExpression.CompareOperators.LT  : SigmaCompareExpression.CompareOperators.GTE,
        SigmaCompareExpression.CompareOperators.LTE : SigmaCompareExpression.CompareOperators.GT,
        SigmaCompareExpression.CompareOperators.GT  : SigmaCompareExpression.CompareOperators.LTE,
        SigmaCompareExpression.CompareOperators.GTE  : SigmaCompareExpression.CompareOperators.LT
    }

    negated_expr : ClassVar[Dict[str, str]] = {
        "{field}=~`{regex}`"   : "{field}!~`{regex}`",
        "{field}!~`{regex}`"   : "{field}=~`{regex}`",
        'field=ip("{value}")'  : 'field!=ip("{value}")',
        'field!=ip("{value}")' : 'field=ip("{value}")',
        "{field}=``"           : '{field}!=``',
        "{field}!=``"          : '{field}=``'
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

    field_query_prefix      : ClassVar[str] = " | %log_parser% | "
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

    # See https://grafana.com/docs/loki/latest/logql/log_queries/#line-filter-expression
    unbound_value_str_expression : ClassVar[str] = '{value}'
    unbound_value_num_expression : ClassVar[str] = '{value}'
    unbound_value_re_expression : ClassVar[str] = '`{value}`'
    # not clearly supported by Sigma?
    unbound_value_cidr_expression : ClassVar[str] = '| ip("{value}")'

    deferred_start : ClassVar[str] = ''
    deferred_end : ClassVar[str] = ''
    deferred_separator : ClassVar[str] = ' '
    deferred_only_query : ClassVar[str] = ''

    # When converting values to regexes, we need to escape the string to prevent use of non-wildcard metacharacters
    # As str equality is case-insensitive in Sigma, but LogQL regexes are case-sensitive, we also prepend with (?i)
    def convert_wildcard_to_re(self, value: SigmaString) -> SigmaRegularExpression:
        """Convert a SigmaString value that (probably) contains wildcards into a regular expression"""
        return SigmaRegularExpression('(?i)'+re.escape(str(value)).replace('\\?', '.').replace('\\*', '.*'))

    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html
    def convert_condition_not(self, cond : ConditionNOT, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        state.processing_state['not_count'] = state.processing_state.get('not_count', 0) + 1
        # ...I hate this already...
        LogQLBackend.eq_token = LogQLBackend.negated_label_filter_operator[LogQLBackend.eq_token]
        LogQLBackend.re_expression = LogQLBackend.negated_expr[LogQLBackend.re_expression]
        LogQLBackend.cidr_expression = LogQLBackend.negated_expr[LogQLBackend.cidr_expression]
        LogQLBackend.field_null_expression = LogQLBackend.negated_expr[LogQLBackend.field_null_expression]
        arg = cond.args[0]
        expr = self.convert_condition(arg, state)
        state.processing_state['not_count'] -= 1
        # ...I still hate this...
        LogQLBackend.eq_token = LogQLBackend.negated_label_filter_operator[LogQLBackend.eq_token]
        LogQLBackend.re_expression = LogQLBackend.negated_expr[LogQLBackend.re_expression]
        LogQLBackend.cidr_expression = LogQLBackend.negated_expr[LogQLBackend.cidr_expression]
        LogQLBackend.field_null_expression = LogQLBackend.negated_expr[LogQLBackend.field_null_expression]
        return expr

    def is_negated(self, state : ConversionState) -> bool:
        return state.processing_state.get('not_count', 0) % 2 == 1

    # Overriding Sigma implementation: change behaviour for negated classes (as args aren't negated until they are converted)
    def compare_precedence(self, outer : ConditionItem, inner : ConditionItem) -> bool:
        outer_class = outer.__class__
        if (inner.__class__ in self.precedence and outer_class in self.precedence):
            if len(list(cls for cls in outer.parent_chain_classes() if cls == ConditionNOT)) % 2 == 1:
                # At this point, we have an odd number of NOTs in the parent chain, outer will have been inverted, but
                # inner will not yet been inverted, and we know inner is either an AND or an OR
                inner_class = ConditionAND if inner.__class__ == ConditionOR else ConditionOR
                return self.precedence.index(inner_class) <= self.precedence.index(outer_class)
        return super().compare_precedence(outer, inner)

    # Overriding Sigma implementation: inverting ANDs and ORs if they are negated
    def convert_condition(self, cond : ConditionItem, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        if self.is_negated(state) and cond.__class__ in self.precedence:
            if isinstance(cond, ConditionAND):
                newcond = ConditionOR(cond.args, cond.source)
            elif isinstance(cond, ConditionOR):
                newcond = ConditionAND(cond.args, cond.source)
            # Update the parent references to reflect the new structure
            newcond.parent = cond.parent
            for arg in cond.args:
                arg.parent = newcond
            return super().convert_condition(newcond, state)
        return super().convert_condition(cond, state)

    # Overriding Sigma implementation: work-around for issue SigmaHQ/pySigma#69
    def convert_condition_group(self, cond : ConditionItem, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        expr = self.convert_condition(cond, state)
        if expr is None or isinstance(expr, DeferredQueryExpression) or len(expr) == 0:
            return expr
        return self.group_expression.format(expr=expr)

    # Overriding Sigma implementation: LogQL does not support OR'd unbounded conditions, but does support |'d searches in regexes
    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        unbound_deferred_or = None
        for arg in cond.args:
            if isinstance(arg, ConditionValueExpression):
                if unbound_deferred_or is None:
                    unbound_deferred_or = LogQLDeferredOrUnboundExpression(state, [], "|~")
                    if self.is_negated(state):
                        unbound_deferred_or.negate()
                unbound_deferred_or.exprs.append(arg.value)
            elif unbound_deferred_or is not None:
                raise SigmaFeatureNotSupportedByBackendError("Operator 'or' not supported by the backend for unbound conditions combined with field conditions", source=cond.source)
        if unbound_deferred_or is not None:
            return unbound_deferred_or
        else:
            return super().convert_condition_or(cond, state)

    # Overriding Sigma implementation: LogQL does not support OR'd AND'd unbounded conditions
    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        if cond.parent_condition_chain_contains(ConditionOR):
            for arg in cond.args:
                if isinstance(arg, ConditionValueExpression):
                    raise SigmaFeatureNotSupportedByBackendError("Operator 'or' not supported by the backend for unbound conditions combined with 'and'", source=cond.source)
        return super().convert_condition_and(cond, state)
    
    # Overriding Sigma implementation: LogQL does not support wildcards - so convert them into regular expressions
    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        # Wildcards (*, ?) are special, but aren't supported in LogQL, so we switch to regex instead
        if cond.value.contains_special():
            cond.value = self.convert_wildcard_to_re(cond.value)
            return self.convert_condition_field_eq_val_re(cond, state)
        else:
            # No wildcards? No problem, we can use the default implementation
            return super().convert_condition_field_eq_val_str(cond, state)

    # As above, but for unbound queries, and wrap in a deferred expression
    def convert_condition_val_str(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        if cond.value.contains_special():
            cond.value = self.convert_wildcard_to_re(cond.value)
            return self.convert_condition_val_re(cond, state)
        expr = LogQLDeferredUnboundExpression(state, self.convert_value_str(cond.value, state))
        if self.is_negated(state):
            expr.negate()
        return expr

    def convert_condition_val_num(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        expr = LogQLDeferredUnboundExpression(state, cond.value)
        if self.is_negated(state):
            expr.negate()
        return expr

    def convert_condition_val_re(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        expr = LogQLDeferredUnboundExpression(state, self.quote_string(self.convert_value_re(cond.value, state)), "|~")
        if self.is_negated(state):
            expr.negate()
        return expr

    def convert_condition_field_compare_op_val(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        if self.is_negated(state):
            cond.value.op = LogQLBackend.negated_cmp_operator[cond.value.op]
        return super().convert_condition_field_compare_op_val(cond, state)

    # Overriding Sigma implementation: use convert_condition rather than convert_condition_or
    def convert_condition_field_eq_expansion(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        or_cond = ConditionOR([
            ConditionFieldEqualsValueExpression(cond.field, value)
            for value in cond.value.values
        ], cond.source)
        return self.convert_condition(or_cond, state)

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
        elif query is None:
            query = ""
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
    
