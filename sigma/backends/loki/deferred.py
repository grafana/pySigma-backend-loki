from dataclasses import dataclass
from enum import auto
from typing import List, Union

from sigma.conversion.deferred import DeferredQueryExpression
from sigma.types import SigmaRegularExpression, SigmaString

from sigma.shared import (
    join_or_values_re,
    negated_line_filter_operator,
    negated_label_filter_operator,
)


class LogQLDeferredType:
    """The different types of deferred expressions that can be created by this backend"""

    STR = auto()
    CIDR = auto()
    REGEXP = auto()
    OR_STR = auto()
    FIELD_REF = auto()


@dataclass
class LogQLDeferredUnboundStrExpression(DeferredQueryExpression):
    """'Defer' unbounded matching to pipelined command **BEFORE** main search expression."""

    value: str
    op: str = "|="  # default to matching

    def negate(self) -> DeferredQueryExpression:
        self.op = negated_line_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        return f"{self.op} {self.value}"


@dataclass
class LogQLDeferredUnboundCIDRExpression(DeferredQueryExpression):
    """'Defer' unbounded matching of CIDR to pipelined command **BEFORE** main search expression."""

    ip: str
    op: str = "|="  # default to matching

    def negate(self) -> DeferredQueryExpression:
        self.op = negated_line_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        return f'{self.op} ip("{self.ip}")'


@dataclass
class LogQLDeferredUnboundRegexpExpression(DeferredQueryExpression):
    """'Defer' unbounded matching of regex to pipelined command **BEFORE** main search
    expression."""

    regexp: str
    op: str = "|~"  # default to matching

    def negate(self) -> DeferredQueryExpression:
        self.op = negated_line_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        if "`" in self.regexp:
            value = '"' + SigmaRegularExpression(self.regexp).escape(('"',)) + '"'
        else:
            value = "`" + self.regexp + "`"
        return f"{self.op} {value}"


@dataclass
class LogQLDeferredOrUnboundExpression(DeferredQueryExpression):
    """'Defer' unbounded OR matching to pipelined command **BEFORE** main search expression."""

    exprs: List[Union[SigmaString, SigmaRegularExpression]]
    op: str = "|~"  # default to matching
    case_insensitive: bool = True

    def negate(self) -> DeferredQueryExpression:
        self.op = negated_line_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        return f"{self.op} {join_or_values_re(self.exprs, self.case_insensitive)}"


@dataclass
class LogQLDeferredLabelFormatExpression(DeferredQueryExpression):
    """'Defer' field reference matching to pipelined command **AFTER** main search expression."""

    label: str
    template: str

    def finalize_expression(self) -> str:
        return f"{self.label}=`{self.template}`"


@dataclass
class LogQLDeferredLabelFilterExpression(DeferredQueryExpression):
    """
    'Defer' generated label matching to after the label_format expressions
    """

    field: str
    op: str = "="
    value: str = "true"

    def negate(self) -> DeferredQueryExpression:
        self.op = negated_label_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        return f"{self.field}{self.op}`{self.value}`"
