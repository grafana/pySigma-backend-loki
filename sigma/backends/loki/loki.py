import copy
import math
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum, auto
from typing import (
    Any,
    ClassVar,
    Deque,
    Dict,
    List,
    NamedTuple,
    Optional,
    Pattern,
    Tuple,
    Union,
)

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
    ParentChainMixin,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError, SigmaError
from sigma.pipelines.loki import LokiCustomAttrs
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCompareExpression,
    SigmaCIDRExpression,
    SigmaRegularExpression,
    SigmaString,
    SigmaNull,
    SigmaNumber,
)
from warnings import warn
from yaml import dump


class LogQLLogParser(
    Enum
):  # would be a little nicer as a StrEnum, requires Python 3.11
    """The different log parsers available in LogQL.

    See: https://grafana.com/docs/loki/latest/logql/log_queries/#parser-expression"""

    JSON = "json"
    LOGFMT = "logfmt"
    PATTERN = "pattern"
    REGEXP = "regexp"
    UNPACK = "unpack"

    def __str__(self):
        return self.value


class LogQLDeferredType:
    """The different types of deferred expressions that can be created by this backend"""

    STR = auto()
    CIDR = auto()
    REGEXP = auto()
    OR_STR = auto()


@dataclass
class LogQLDeferredUnboundStrExpression(DeferredQueryExpression):
    """'Defer' unbounded matching to pipelined command **BEFORE** main search expression."""

    value: str
    op: str = "|="  # default to matching

    def negate(self) -> DeferredQueryExpression:
        self.op = LogQLBackend.negated_line_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        return f"{self.op} {self.value}"


@dataclass
class LogQLDeferredUnboundCIDRExpression(DeferredQueryExpression):
    """'Defer' unbounded matching of CIDR to pipelined command **BEFORE** main search expression."""

    ip: str
    op: str = "|="  # default to matching

    def negate(self) -> DeferredQueryExpression:
        self.op = LogQLBackend.negated_line_filter_operator[self.op]
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
        self.op = LogQLBackend.negated_line_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        if "`" in self.regexp:
            value = '"' + SigmaRegularExpression(self.regexp).escape('"') + '"'
        else:
            value = "`" + self.regexp + "`"
        return f"{self.op} {value}"


@dataclass
class LogQLDeferredOrUnboundExpression(DeferredQueryExpression):
    """'Defer' unbounded OR matching to pipelined command **BEFORE** main search expression."""

    exprs: List[Union[SigmaString, SigmaRegularExpression]]
    op: str = "|~"  # default to matching

    def negate(self) -> DeferredQueryExpression:
        self.op = LogQLBackend.negated_line_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        case_insensitive = any(
            val.regexp.startswith("(?i)")
            for val in self.exprs
            if isinstance(val, SigmaRegularExpression)
        )
        or_value = "|".join(
            (
                re.escape(str(val))
                if isinstance(val, SigmaString)
                else re.sub("^\\(\\?i\\)", "", val.regexp)
                for val in self.exprs
            )
        )
        if case_insensitive:
            or_value = "(?i)" + or_value
        if "`" in or_value:
            or_value = '"' + SigmaRegularExpression(or_value).escape('"') + '"'
        else:
            or_value = "`" + or_value + "`"
        return f"{self.op} {or_value}"


LogQLLineFilterInfo = NamedTuple(
    "LogQLLineFilterInfo",
    [("value", str), ("negated", bool), ("deftype", auto)],
)


class LogQLBackend(TextQueryBackend):
    """Loki LogQL query backend. Generates LogQL queries as described in the Loki documentation:

    https://grafana.com/docs/loki/latest/logql/log_queries/"""

    # The backend generates grouping if required
    name: ClassVar[str] = "Grafana Loki"
    formats: Dict[str, str] = {
        "default": "Plain Loki queries",
        "ruler": "Loki 'ruler' output format for generating alerts",
    }

    negated_line_filter_operator: ClassVar[Dict[str, str]] = {
        "|=": "!=",
        "!=": "|=",
        "|~": "!~",
        "!~": "|~",
    }

    negated_label_filter_operator: ClassVar[Dict[str, str]] = {"=": "!=", "!=": "="}

    negated_cmp_operator: ClassVar[
        Dict[
            SigmaCompareExpression.CompareOperators,
            SigmaCompareExpression.CompareOperators,
        ]
    ] = {
        SigmaCompareExpression.CompareOperators.LT: SigmaCompareExpression.CompareOperators.GTE,
        SigmaCompareExpression.CompareOperators.LTE: SigmaCompareExpression.CompareOperators.GT,
        SigmaCompareExpression.CompareOperators.GT: SigmaCompareExpression.CompareOperators.LTE,
        SigmaCompareExpression.CompareOperators.GTE: SigmaCompareExpression.CompareOperators.LT,
    }

    negated_expr: ClassVar[Dict[str, str]] = {
        "{field}=~{regex}": "{field}!~{regex}",
        "{field}!~{regex}": "{field}=~{regex}",
        '{field}=ip("{value}")': '{field}!=ip("{value}")',
        '{field}!=ip("{value}")': '{field}=ip("{value}")',
        "{field}=``": "{field}!=``",
        "{field}!=``": "{field}=``",
    }

    # Operator precedence: tuple of Condition{AND,OR} in order of precedence.
    # LogQL lacks a NOT operator - is replicated by applying De Morgan's laws instead
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem]] = (
        ConditionAND,
        ConditionOR,
    )
    # Expression for precedence override grouping as format string with {expr} placeholder
    group_expression: ClassVar[str] = "({expr})"

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    eq_token: ClassVar[
        str
    ] = "="  # Token inserted between field and value (without separator)

    # Rather than picking between "s and `s, defaulting to `s
    str_quote: ClassVar[str] = "`"
    escape_char: ClassVar[str] = "\\"
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""

    field_replace_pattern: ClassVar[Pattern] = re.compile("[^a-zA-Z0-9_:]+")
    field_null_expression: ClassVar[str] = "{field}=``"

    # LogQL does not support wildcards, so we convert them to regular expressions
    wildcard_multi: ClassVar[
        str
    ] = "*"  # Character used as multi-character wildcard (replaced with .*)
    wildcard_single: ClassVar[
        str
    ] = "?"  # Character used as single-character wildcard (replaced with .)

    # Regular expressions
    re_expression: ClassVar[str] = "{field}=~{regex}"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Optional[Tuple[str]]] = None

    # cidr expressions
    cidr_expression: ClassVar[str] = '{field}=ip("{value}")'

    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # See https://grafana.com/docs/loki/latest/logql/log_queries/#line-filter-expression
    unbound_value_str_expression: ClassVar[str] = "{value}"
    unbound_value_num_expression: ClassVar[str] = "{value}"
    unbound_value_re_expression: ClassVar[str] = "{value}"
    # not clearly supported by Sigma?
    unbound_value_cidr_expression: ClassVar[str] = '| ip("{value}")'

    deferred_start: ClassVar[str] = ""
    deferred_separator: ClassVar[str] = " "
    deferred_only_query: ClassVar[str] = ""

    # Loki-specific functions
    # When converting values to regexes, we need to escape the string to prevent use of
    # non-wildcard metacharacters
    # As str equality is case-insensitive in Sigma, but LogQL regexes are case-sensitive,
    # we also prepend with (?i)
    def convert_wildcard_to_re(self, value: SigmaString) -> SigmaRegularExpression:
        """Convert a SigmaString value that contains wildcards into a regular expression"""
        return SigmaRegularExpression(
            "(?i)" + re.escape(str(value)).replace("\\?", ".").replace("\\*", ".*")
        )

    def select_log_parser(self, rule: SigmaRule) -> Union[str, LogQLLogParser]:
        """Select a relevant log parser based on common approaches to ingesting data into Loki.
        Currently defaults to logfmt, but will use the json parser for Windows, Azure and Zeek
        signatures."""
        if LokiCustomAttrs.PARSER.value in rule.custom_attributes:
            return rule.custom_attributes[LokiCustomAttrs.PARSER.value]
        # TODO: this currently supports two commonly used formats -
        # more advanced parser formats would be required/more efficient for other sources
        if rule.logsource.product in ("windows", "azure", "zeek"):
            # Most Windows log data comes from EventLog, and both Promtail and FluentD
            # exporters produce JSON output for Loki.
            # Azure log data also arrives in Loki in JSON format, via the Logstash exporter
            # - Note: if you are using the Azure data source in Grafana, the query language
            # is Kusto QL
            # Zeek's default log file format (TSV) is not clearly supported by promtail/loki - but
            # fortunately Zeek also offers a JSON format alternative.
            # See:
            #  - https://grafana.com/docs/loki/latest/clients/promtail/scraping/#windows-event-log  # noqa: E501
            #  - https://blog.e-mundo.de/post/painless-and-secure-windows-event-log-delivery-with-fluent-bit-loki-and-grafana/  # noqa: E501
            #  - https://www.elastic.co/guide/en/logstash/current/plugins-inputs-azure_event_hubs.html  # noqa: E501
            #  - https://docs.zeek.org/en/master/log-formats.html#zeek-json-format-logs
            return LogQLLogParser.JSON
        # default to logfmt - relevant for auditd, and many other applications
        return LogQLLogParser.LOGFMT

    def select_log_stream(self, rule: SigmaRule) -> str:
        """Select a logstream based on the logsource information included within a rule and
        following the assumptions described in select_log_parser."""
        if LokiCustomAttrs.LOGSOURCE_SELECTION.value in rule.custom_attributes:
            return rule.custom_attributes[LokiCustomAttrs.LOGSOURCE_SELECTION.value]
        logsource = rule.logsource
        if logsource.product == "windows":
            return '{job=~"eventlog|winlog|windows|fluentbit.*"}'
        if logsource.product == "azure":
            return '{job="logstash"}'
        # By default, bring back all log streams
        return '{job=~".+"}'

    def sanitize_label_key(self, key: str, isprefix: bool = True) -> str:
        """Implements the logic used by Loki to sanitize labels.

        See: https://github.com/grafana/loki/blob/main/pkg/logql/log/util.go#L21"""
        # pySigma treats null or empty fields as unbound expressions, rather than keys
        if key is None or len(key) == 0:  # pragma: no cover
            return ""
        key = key.strip()
        if len(key) == 0:
            return key
        if isprefix and key[0] >= "0" and key[0] <= "9":
            key = "_" + key
        return "".join(
            (
                r
                if (r >= "a" and r <= "z")
                or (r >= "A" and r <= "Z")
                or r == "_"
                or (r >= "0" and r <= "9")
                else "_"
                for r in key
            )
        )

    # Implementing negation through De Morgan's laws
    def is_negated(self, state: ConversionState) -> bool:
        """A utility function for determining whether or not the current operation
        should be negated or not, based on the count of NOT operations, maintainined
        in the processing state."""
        return state.processing_state.get("not_count", 0) % 2 == 1

    def is_negated_chain(self, cond: ParentChainMixin) -> bool:
        """A utility function for determining whether or not the current operation
        should be negated, based on the count of NOT operations in the parent chain
        class. This will be less efficient than is_negated(), but is required when we
        lack the processing state."""
        return (
            len(
                list(
                    parent
                    for parent in cond.parent_chain_classes()
                    if parent == ConditionNOT
                )
            )
            % 2
            == 1
        )

    def partition_rule(
        self, condition: ParentChainMixin, partitions: int
    ) -> List[ParentChainMixin]:
        """Given a rule that is (probably) going to generate a query that is longer
        than the maximum query length for LogQL, break it into smaller conditions, by
        identifying the highest level OR in the parse tree and equally dividing its
        arguments between copies of the same rule.

        Notes:
            This code makes a number of assumptions about a rule:
             - a rule contains at least one OR (warning if one can't be found)
             - all arguments of the top-OR are same length (likely a bad assumption!)
             - if we had multiple parsed_conditions, they each need processing
               separately
        """
        new_conditions: List[ParentChainMixin] = []
        for part_ind in range(partitions):
            condition_copy = copy.deepcopy(condition)
            # Find the top-OR and partition it
            found_or = False
            conditions = Deque[ParentChainMixin]()
            conditions.append(condition_copy)
            while conditions:
                # breadth-first search the parse tree to find the highest OR
                cond = conditions.popleft()
                if (
                    isinstance(cond, ConditionOR) and not self.is_negated_chain(cond)
                ) or (isinstance(cond, ConditionAND) and self.is_negated_chain(cond)):
                    arg_count = len(cond.args)
                    # If we need more partitions than arguments to the top OR, try with
                    # just that many
                    if arg_count < partitions:
                        warn(
                            f"Too few arguments to highest OR, reducing partition "
                            f"count to {arg_count}",
                        )
                        return self.partition_rule(condition, arg_count)
                    start = part_ind * int(arg_count / partitions)
                    end = (part_ind + 1) * int(arg_count / partitions)
                    cond.args = cond.args[start:end]
                    found_or = True
                    break
                if cond.operator:
                    for arg in cond.args:
                        conditions.append(arg)
            if not found_or:
                # No OR statement within the large query, so probably no way of
                # dividing query
                warn(
                    "Cannot partition a rule that exceeds query length limits "
                    "due to lack of ORs",
                )
                return [condition]
            new_conditions.append(condition_copy)
        return new_conditions

    def convert_field_expression_to_line_filter(
        self,
        expr: ConditionFieldEqualsValueExpression,
        log_parser: Union[str, LogQLLogParser],
        is_negated: bool,
    ) -> Optional[LogQLLineFilterInfo]:
        """Given a field expression, attempt to convert it into a valid line filter
        that can be added to a query to improve its performance without reducing the
        number of results that will be produced by that query. Returns None if no such
        filter can be created."""
        # Can only use negation of expressions if the log format includes the field
        # name in the log line
        if log_parser is LogQLLogParser.LOGFMT and isinstance(
            expr.value, (SigmaString, SigmaNumber, SigmaBool, SigmaNull)
        ):
            value = "" if isinstance(expr.value, SigmaNull) else str(expr.value)
            return LogQLLineFilterInfo(
                value=f"{expr.field}={value}",
                negated=is_negated,
                deftype=LogQLDeferredType.STR,
            )
        elif (
            isinstance(expr.value, (SigmaString, SigmaNumber, SigmaBool))
            and not is_negated
        ):
            return LogQLLineFilterInfo(
                value=str(expr.value),
                negated=is_negated,
                deftype=LogQLDeferredType.STR,
            )
        elif isinstance(expr.value, SigmaRegularExpression):
            # Could include field name if entries are logfmt and doesn't start with wildcard
            return LogQLLineFilterInfo(
                value=expr.value.regexp,
                negated=is_negated,
                deftype=LogQLDeferredType.REGEXP,
            )
        elif isinstance(expr.value, SigmaCIDRExpression):
            # Could include field name if entries are logfmt
            return LogQLLineFilterInfo(
                value=expr.value.cidr,
                negated=is_negated,
                deftype=LogQLDeferredType.CIDR,
            )
        else:
            # Can't necessarily assume the field will appear in the log file for an
            # arbitary log format
            return None

    def find_longest_common_string_line_filter(
        self,
        candidates: List[Optional[LogQLLineFilterInfo]],
        log_parser: Union[str, LogQLLogParser],
    ) -> Optional[LogQLLineFilterInfo]:
        """Finds the longest line filter that will match all of the candidate line
        filters provided, using difflib's SequenceMatcher to find the relevant
        string. All candidate values cannot be None, must not be negated, and must be
        string values."""
        # If, for *any* of the candidates, no valid line filter was generated, they are
        # negated, or they are not strings, we cannot ensure that the generated filter
        # will necessarily catch all arguments and we must return no filter
        any_issues = any(
            (cand is None or cand.negated or cand.deftype is not LogQLDeferredType.STR)
            for cand in candidates
        )
        if any_issues:
            return None
        matcher = None
        match = None
        # Finding the longest common substring of a list of strings, by repeatedly
        # calling SequenceMatcher's find_longest_match. The 1st candidate is cached
        # in the 2nd sequence (b), then following candidates are set as the 1st
        # sequence (a). The longest match between a and b is then found, each time
        # reducing the search region of b based on the previous match.
        # See: https://docs.python.org/3/library/difflib.html#difflib.SequenceMatcher
        for cand in candidates:
            if matcher is None:
                # First iteration: initialise sequence matcher with the first
                # candidate as sequence 2
                # mypy doesn't spot that the previous check will prevent cand = None
                matcher = SequenceMatcher(None, b=cand.value)  # type: ignore
            else:
                # Subsequent iterations: use the current candidate as sequence 1
                matcher.set_seq1(cand.value)
                # If we've previously found a match, only use the current matched
                # region in b for this search, otherwise use the whole string
                blo = match.b if match else 0
                bhi = match.b + match.size if match else len(matcher.b)
                match = matcher.find_longest_match(0, len(cand.value), blo, bhi)
                # If the current match length is 0, there was no common substring
                # between all of the candidates found using this greedy strategy
                if match.size == 0:
                    return None
        if matcher and match:
            start = match.b
            end = match.b + match.size
            return LogQLLineFilterInfo(
                value=matcher.b[start:end],
                negated=False,
                deftype=LogQLDeferredType.STR,
            )
        return None

    def generate_candidate_line_filter(
        self, cond: ParentChainMixin, log_parser: Union[str, LogQLLogParser]
    ) -> Optional[LogQLLineFilterInfo]:
        """Given a condition, attempt to find the longest string in queries that could
        be used as line filters, which should improve the overall performance of the
        generated Loki queries."""
        is_negated = self.is_negated_chain(cond)
        if isinstance(cond, ConditionFieldEqualsValueExpression):
            return self.convert_field_expression_to_line_filter(
                cond, log_parser, is_negated
            )
        # AND clauses: any of the values could be true - so pick the longest one
        if (isinstance(cond, ConditionAND) and not is_negated) or (
            isinstance(cond, ConditionOR) and is_negated
        ):
            candidates = [
                self.generate_candidate_line_filter(arg, log_parser)
                for arg in cond.args
            ]
            longest = None
            for cand in candidates:
                if cand and (longest is None or len(cand.value) > len(longest.value)):
                    longest = cand
            return longest
        # OR clauses: all of the values must be possible, so we can use the LCS of
        # them all
        elif (isinstance(cond, ConditionOR) and not is_negated) or (
            isinstance(cond, ConditionAND) and is_negated
        ):
            candidates = [
                self.generate_candidate_line_filter(arg, log_parser)
                for arg in cond.args
            ]
            # The longest common substring of all the arguments is permissible as a
            # line filter, as every candidate must contain at least that string
            return self.find_longest_common_string_line_filter(candidates, log_parser)
        elif isinstance(cond, ConditionNOT):
            return self.generate_candidate_line_filter(cond.args[0], log_parser)
        else:  # pragma: no cover
            # The above should cover all existing Sigma classes, but just in case...
            raise SigmaError(
                f"Unhandled type by Loki backend: {str(cond.__class__.__name__)}"
            )

    # Overriding Sigma TextQueryBackend functionality as necessary
    def convert_rule(
        self, rule: SigmaRule, output_format: Optional[str] = None
    ) -> List[str]:
        """
        Convert a single Sigma rule into one or more queries, based on the maximum
        estimated length of a generated query. Largely copied from pySigma, with
        modifications for partitioning rules into smaller queries.
        """
        state = ConversionState()
        attempted_conversion = False
        attempt_shortening = False
        try:
            processing_pipeline = (
                self.backend_processing_pipeline
                + self.processing_pipeline
                + self.output_format_processing_pipeline[
                    output_format or self.default_format
                ]
            )

            error_state = "applying processing pipeline on"
            processing_pipeline.apply(rule)  # 1. Apply transformations
            state.processing_state = processing_pipeline.state

            # When finalising a query from a condition, the index it is associated with
            # is the index of the parsed_condition from the rule detection. As this
            # code may partition one or more of these conditions into multiple
            # conditions, we explicitly associate them together here so the
            # relationship can be maintained throughout.
            conditions = [
                (index, cond.parsed)
                for index, cond in enumerate(rule.detection.parsed_condition)
            ]
            shortened_conditions: List[Tuple[int, ParentChainMixin]] = []
            final_queries: List[str] = []

            threshold_length = 4096  # 80% of Loki limit (5120) due to query expansion
            while not attempted_conversion or attempt_shortening:
                if attempt_shortening:
                    conditions = shortened_conditions
                    attempt_shortening = False

                error_state = "converting"
                queries = [  # 2. Convert condition
                    (index, self.convert_condition(cond, state))
                    for index, cond in conditions
                ]

                for index, query in queries:
                    if not state.has_deferred() and self.config.get(
                        "add_line_filters", False
                    ):
                        # 2.5. Introduce line filters
                        error_state = "introducing line filters"
                        log_parser = self.select_log_parser(rule)
                        candidate_lfs = [
                            self.generate_candidate_line_filter(cond, log_parser)
                            for _, cond in conditions
                        ]
                        if candidate_lfs and candidate_lfs[0] is not None:
                            value, negated, def_type = candidate_lfs[0]
                            if def_type is LogQLDeferredType.STR:
                                line_filter = LogQLDeferredUnboundStrExpression(
                                    state,
                                    self.convert_value_str(SigmaString(value), state),
                                )
                            elif def_type is LogQLDeferredType.REGEXP:
                                line_filter = LogQLDeferredUnboundRegexpExpression(
                                    state, value
                                )
                            elif def_type is LogQLDeferredType.CIDR:
                                line_filter = LogQLDeferredUnboundCIDRExpression(
                                    state, value
                                )
                            if negated:
                                line_filter.negate()

                    error_state = "finalizing query for"
                    final_query = self.finalize_query(
                        rule, query, index, state, output_format or self.default_format
                    )
                    if len(final_query) < threshold_length:
                        # If the query is within the threshold length, all is well
                        final_queries.append(final_query)
                    elif not attempted_conversion:
                        # If this is the first pass, try to shorten the condition
                        shortened_conditions.extend(
                            (index, cond)  # Ensure the index-cond remain associated
                            for cond in self.partition_rule(
                                conditions[index][1],
                                math.ceil(len(final_query) / threshold_length),
                            )
                        )
                        attempt_shortening = True
                    else:
                        # Otherwise, produce the query anyway
                        final_queries.append(final_query)
                attempted_conversion = True
            return final_queries

        except SigmaError as e:
            if self.collect_errors:
                self.errors.append((rule, e))
                return []
            else:
                raise e
        except Exception as e:  # pragma: no cover
            # enrich all other exceptions with Sigma-specific context information
            msg = f" (while {error_state} rule {str(rule.source)})"
            if len(e.args) > 1:
                e.args = (e.args[0] + msg,) + e.args[1:]
            else:
                e.args = (e.args[0] + msg,)
            raise

    def convert_value_re(
        self, r: SigmaRegularExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Loki does not need to do any additional escaping for regular expressions if we can
        use the tilde character"""
        if "`" in r.regexp:
            return '"' + r.escape('"') + '"'
        return "`" + r.regexp + "`"

    def convert_condition_not(
        self, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions through application of De Morgan's laws."""
        state.processing_state["not_count"] = (
            state.processing_state.get("not_count", 0) + 1
        )
        # As the TextQueryBackend doesn't break these patterns into constituent operators,
        # we need to change the class variables to reflect the negation of the relevant operations
        LogQLBackend.eq_token = LogQLBackend.negated_label_filter_operator[
            LogQLBackend.eq_token
        ]
        LogQLBackend.re_expression = LogQLBackend.negated_expr[
            LogQLBackend.re_expression
        ]
        LogQLBackend.cidr_expression = LogQLBackend.negated_expr[
            LogQLBackend.cidr_expression
        ]
        LogQLBackend.field_null_expression = LogQLBackend.negated_expr[
            LogQLBackend.field_null_expression
        ]
        arg = cond.args[0]
        expr = self.convert_condition(arg, state)
        state.processing_state["not_count"] -= 1
        # Once the negated sub-tree has been processed, we can revert them back to
        # their prior behaviour
        LogQLBackend.eq_token = LogQLBackend.negated_label_filter_operator[
            LogQLBackend.eq_token
        ]
        LogQLBackend.re_expression = LogQLBackend.negated_expr[
            LogQLBackend.re_expression
        ]
        LogQLBackend.cidr_expression = LogQLBackend.negated_expr[
            LogQLBackend.cidr_expression
        ]
        LogQLBackend.field_null_expression = LogQLBackend.negated_expr[
            LogQLBackend.field_null_expression
        ]
        return expr

    # Change behaviour for negated classes (as args aren't negated until they are converted)
    def compare_precedence(self, outer: ConditionItem, inner: ConditionItem) -> bool:
        """As this implements negation by changing the sub-tree and swapping ANDs and ORs,
        the precedence rules for such operators also needs to be flipped."""
        outer_class = outer.__class__
        inner_class = inner.__class__
        if inner_class is ConditionNOT:
            # We need to peek inside a NOT to check whether the precedence rules apply
            # A ConditionNOT should contain at most one argument
            if len(inner.args) == 1:
                inner = inner.args[0]
                inner_class = inner.__class__
        if inner_class in self.precedence and outer_class in self.precedence:
            if self.is_negated_chain(inner):
                # At this point, we have an odd number of NOTs in the parent chain, outer
                # will have been inverted, but inner will not yet been inverted, and we
                # know inner is either an AND or an OR
                inner_class = (
                    ConditionAND if inner_class == ConditionOR else ConditionOR
                )
                return self.precedence.index(inner_class) <= self.precedence.index(
                    outer_class
                )
        return super().compare_precedence(outer, inner)

    # Inverting ANDs and ORs if they are negated
    def convert_condition(
        self, cond: ConditionItem, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Checks if the current boolean binary operator is being negated, and applies the change,
        keeping the same arguments and history."""
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

    # Work-around for issue SigmaHQ/pySigma#69
    def convert_condition_group(
        self, cond: ConditionItem, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Ensure that if an expression is a deferred query, it isn't forced into a string
        representation."""
        expr = self.convert_condition(cond, state)
        if expr is None or isinstance(expr, DeferredQueryExpression) or len(expr) == 0:
            return expr
        return self.group_expression.format(expr=expr)

    # LogQL does not support OR'd unbounded conditions, but does support |'d searches in regexes
    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Implements OR'd unbounded conditions as a regex that combines the search terms
        with |s."""
        unbound_deferred_or = None
        for arg in cond.args:
            if isinstance(arg, ConditionValueExpression):
                if unbound_deferred_or is None:
                    unbound_deferred_or = LogQLDeferredOrUnboundExpression(
                        state, [], "|~"
                    )
                    if self.is_negated(state):
                        unbound_deferred_or.negate()
                if arg.value.contains_special():
                    unbound_deferred_or.exprs.append(
                        self.convert_wildcard_to_re(arg.value)
                    )
                else:
                    unbound_deferred_or.exprs.append(arg.value)
            elif unbound_deferred_or is not None:
                raise SigmaFeatureNotSupportedByBackendError(
                    "Operator 'or' not supported by the backend for unbound conditions combined "
                    "with field conditions",
                    source=cond.source,
                )
        if unbound_deferred_or is not None:
            return unbound_deferred_or
        else:
            joiner = self.token_separator + self.or_token + self.token_separator

            return joiner.join(
                (
                    converted
                    for converted in (
                        self.convert_condition(arg, state)
                        if self.compare_precedence(cond, arg)
                        else self.convert_condition_group(arg, state)
                        for arg in cond.args
                    )
                    if converted is not None
                    and not isinstance(converted, DeferredQueryExpression)
                    and len(converted) > 0
                )
            )

    # LogQL does not support OR'd AND'd unbounded conditions
    def convert_condition_and(
        self, cond: ConditionAND, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Checks that unbounded conditions are not also being combined with ORs
        (as we cannot implement such an expression with regexes)."""
        if cond.parent_condition_chain_contains(ConditionOR):
            for arg in cond.args:
                if isinstance(arg, ConditionValueExpression):
                    raise SigmaFeatureNotSupportedByBackendError(
                        "Operator 'or' not supported by the backend for unbound conditions "
                        "combined with 'and'",
                        source=cond.source,
                    )
        joiner = self.token_separator + self.and_token + self.token_separator
        return joiner.join(
            (
                converted
                for converted in (
                    self.convert_condition(arg, state)
                    if self.compare_precedence(cond, arg)
                    else self.convert_condition_group(arg, state)
                    for arg in cond.args
                )
                if converted is not None
                and not isinstance(converted, DeferredQueryExpression)
                and len(converted) > 0
            )
        )

    # LogQL does not support wildcards - so convert them into regular expressions
    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Converts all wildcard conditions on fields into regular expression queries, replacing
        wildcards with appropriate regex metacharacters."""
        # Wildcards (*, ?) are special, but aren't supported in LogQL, so we switch to regex instead
        if cond.value.contains_special():
            cond.value = self.convert_wildcard_to_re(cond.value)
            return self.convert_condition_field_eq_val_re(cond, state)
        else:
            # No wildcards? No problem, we can use the default implementation
            return super().convert_condition_field_eq_val_str(cond, state)

    # As above, but for unbound queries, and wrap in a deferred expression
    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Converts all unbound wildcard conditions into regular expression queries,
        replacing wildcards with appropriate regex metacharacters."""
        if cond.value.contains_special():
            cond.value = self.convert_wildcard_to_re(cond.value)
            return self.convert_condition_val_re(cond, state)
        expr = LogQLDeferredUnboundStrExpression(
            state, self.convert_value_str(cond.value, state)
        )
        if self.is_negated(state):
            expr.negate()
        return expr

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Convert unbound numeric queries into deferred line filters."""
        expr = LogQLDeferredUnboundStrExpression(state, cond.value)
        if self.is_negated(state):
            expr.negate()
        return expr

    def convert_condition_val_re(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[None, str, DeferredQueryExpression]:
        """Convert unbound regular expression queries into deferred line filters."""
        # Strip outer zero-length wildcards (.*), as they are implicit in a Loki line filter
        # Use a RE to determine if the RE starts and/or ends with .* (ignoring flags ^(?.+))
        outer_wildcards = re.match(
            "^(?P<flag>\\(\\?.+\\))?(?P<lead>\\.\\*)?(?P<body>.*?)(?P<trail>\\.\\*)?$",
            cond.value.regexp,
        )
        # Ignoring optional captures, this regex resolves to ^(.*?)$ - which should
        # capture all possible inputs, but we should check just-in-case
        if not outer_wildcards:
            return None  # pragma: no cover
        if outer_wildcards.group("lead") or outer_wildcards.group("trail"):
            if len(outer_wildcards.group("body")) > 0:
                flag = outer_wildcards.group("flag") or ""
                cond.value.regexp = flag + outer_wildcards.group("body")
            else:
                # If there's no value between these wildcards, we can ignore the filter
                return None
        expr = LogQLDeferredUnboundStrExpression(
            state, self.convert_value_re(cond.value, state), "|~"
        )
        if self.is_negated(state):
            expr.negate()
        return expr

    # Although implemented in pySigma, there does not currently seem to be a way of writing
    # Sigma rules that incorporate (the negation of) comparison operations, so ignore for
    # code coverage purposes
    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:  # pragma: no cover
        """When converting numeric comparison operations, if they are negated, swap to the opposite
        comparison (i.e., < becomes >=, >= becomes <, etc)."""
        if self.is_negated(state):
            cond.value.op = LogQLBackend.negated_cmp_operator[cond.value.op]
        return super().convert_condition_field_compare_op_val(cond, state)

    # Use convert_condition rather than convert_condition_or
    # (which prevented negation from being applied)
    def convert_condition_field_eq_expansion(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Ensures that the OR condition created when expanding an equality for many values
        goes through convert_condition, rather than convert_condition_or, as it would
        circumvent it's negation."""
        or_cond = ConditionOR(
            [
                ConditionFieldEqualsValueExpression(cond.field, value)
                for value in cond.value.values
            ],
            cond.source,
        )
        return self.convert_condition(or_cond, state)

    # Loki has strict rules about field (label) names, so use their rules
    def escape_and_quote_field(self, field_name: str) -> str:
        """Use Loki's sanitize function to ensure the field name is appropriately escaped."""
        return self.sanitize_label_key(field_name)

    # If a string doesn't contain a tilde character, easier to use it to quote strings,
    # otherwise we will default to using a double quote character, and escape the string
    # appropriately
    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """By default, use the tilde character to quote fields, which needs limited escaping.
        If the value contains a tilde character, use double quotes and apply more rigourous
        escaping."""
        quote = "`"
        if any([c == quote for c in s]):
            quote = '"'
        # If our string doesn't contain any tilde characters
        if quote == "`":
            converted = s.convert()
        else:
            converted = s.convert(escape_char="\\", add_escaped='"\\')
        return quote + converted + quote

    # Swapping the meaning of "deferred" expressions so they appear at the start of a query,
    # rather than the end (since this is the recommended approach for LogQL), and add in log
    # stream selectors & parser
    def finalize_query(
        self,
        rule: SigmaRule,
        query: Union[str, DeferredQueryExpression],
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> Union[str, DeferredQueryExpression]:
        """Complete the conversion of the query, selecting an appropriate log parser if necessary,
        and pre-pending deferred line filters."""
        if isinstance(query, DeferredQueryExpression):
            query = self.deferred_only_query
        elif query is not None and len(query) > 0:
            # selecting an appropriate log parser to use
            query = f"| {str(self.select_log_parser(rule))} | {query}"
        elif query is None:
            query = ""
        if state.has_deferred():
            query = self.deferred_separator.join(
                (
                    deferred_expression.finalize_expression()
                    for deferred_expression in state.deferred
                )
            ) + (" " + query if len(query) > 0 else "")
            # Since we've already processed the deferred parts, we can clear them
            state.deferred.clear()
        if rule.fields and len(rule.fields) > 0:
            line_fmt_fields = " ".join(
                "{{." + self.sanitize_label_key(field) + "}}" for field in rule.fields
            )
            query = query + f' | line_format "{line_fmt_fields}"'
        # Select an appropriate source based on the logsource
        query = self.select_log_stream(rule) + " " + query
        return super().finalize_query(rule, query, index, state, output_format)

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        return query

    def finalize_output_default(self, queries: List[str]) -> List[str]:
        return list(queries)

    def finalize_query_ruler(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict[str, Any]:
        """Use information from the Sigma rule to produce human readable information for
        an alert."""
        alert = self.field_replace_pattern.sub("_", rule.title).strip("_")
        ruler = {
            "alert": alert,
            "annotations": {"description": rule.description, "summary": rule.title},
            "expr": f"sum(count_over_time({query} [1m])) or vector(0) > 0",
            "labels": {},
        }
        if rule.level:
            ruler["labels"]["severity"] = rule.level.name.lower()  # type: ignore
        return ruler

    def finalize_output_ruler(self, queries: List[Dict[str, Any]]) -> str:
        """Produce a collection of alert queries bundled together in a single Loki ruler
        YAML format."""
        rules = {"groups": [{"name": "Sigma rules", "rules": queries}]}
        return dump(rules)
