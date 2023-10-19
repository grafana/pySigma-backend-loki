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
from sigma.pipelines.loki import LokiCustomAttributes
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
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
    case_insensitive: bool = True

    def negate(self) -> DeferredQueryExpression:
        self.op = LogQLBackend.negated_line_filter_operator[self.op]
        return self

    def finalize_expression(self) -> str:
        # This makes the regex case insensitive if any values are SigmaStrings
        # or if any of the regexes are case insensitive
        # TODO: can we make this more precise?
        case_insensitive = any(
            (
                isinstance(val, SigmaString)
                and self.case_insensitive
                and not isinstance(val, SigmaCasedString)
            )
            or (
                isinstance(val, SigmaRegularExpression)
                and val.regexp.startswith("(?i)")
            )
            for val in self.exprs
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
    identifier: ClassVar[str] = "loki"
    formats: Dict[str, str] = {
        "default": "Plain Loki queries",
        "ruler": "Loki 'ruler' output format for generating alerts",
    }
    requires_pipeline: ClassVar[bool] = False

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

    # Rather than picking between "s and `s, defaulting to `s
    str_quote: ClassVar[str] = "`"
    escape_char: ClassVar[str] = "\\"
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""

    field_replace_pattern: ClassVar[Pattern] = re.compile("[^a-zA-Z0-9_:]+")

    negated_line_filter_operator: ClassVar[Dict[str, str]] = {
        "|=": "!=",
        "!=": "|=",
        "|~": "!~",
        "!~": "|~",
    }

    current_templates: ClassVar[Union[bool, None]] = None
    # Leave this to be set by the below function
    eq_token: ClassVar[str]
    field_null_expression: ClassVar[str]
    re_expression: ClassVar[str]
    cidr_expression: ClassVar[str]
    compare_op_expression: ClassVar[str]
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]]
    case_sensitive_match_expression: ClassVar[str]

    @staticmethod
    def set_expression_templates(negated: bool) -> None:
        """When converting field expressions, the TextBackend class uses the below
        variables to format the rule. As LogQL applies negation directly via
        expressions, we need to dynamically update these depending on whether the
        expression was negated or not."""
        if negated == LogQLBackend.current_templates:
            return  # nothing to do!
        if not negated:
            LogQLBackend.eq_token = "="
            LogQLBackend.field_null_expression = "{field}=``"
            LogQLBackend.re_expression = "{field}=~{regex}"
            LogQLBackend.cidr_expression = '{field}=ip("{value}")'
            LogQLBackend.compare_operators = {
                SigmaCompareExpression.CompareOperators.LT: "<",
                SigmaCompareExpression.CompareOperators.LTE: "<=",
                SigmaCompareExpression.CompareOperators.GT: ">",
                SigmaCompareExpression.CompareOperators.GTE: ">=",
            }
            LogQLBackend.case_sensitive_match_expression = "{field}={value}"
        else:
            LogQLBackend.eq_token = "!="
            LogQLBackend.field_null_expression = "{field}!=``"
            LogQLBackend.re_expression = "{field}!~{regex}"
            LogQLBackend.cidr_expression = '{field}!=ip("{value}")'
            LogQLBackend.compare_operators = {
                SigmaCompareExpression.CompareOperators.LT: ">=",
                SigmaCompareExpression.CompareOperators.LTE: ">",
                SigmaCompareExpression.CompareOperators.GT: "<=",
                SigmaCompareExpression.CompareOperators.GTE: "<",
            }
            LogQLBackend.case_sensitive_match_expression = "{field}!={value}"
        # Cache the state of these variables so we don't keep setting them needlessly
        LogQLBackend.current_templates = negated

    # LogQL does not support wildcards, but we convert them to regular expressions
    # Character used as multi-character wildcard (replaced with .*)
    wildcard_multi: ClassVar[str] = "*"
    # Character used as single-character wildcard (replaced with .)
    wildcard_single: ClassVar[str] = "?"

    # Regular expressions
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Optional[Tuple[str]]] = None

    unbound_value_str_expression: ClassVar[str] = "{value}"
    unbound_value_num_expression: ClassVar[str] = "{value}"
    unbound_value_re_expression: ClassVar[str] = "{value}"
    unbound_value_cidr_expression: ClassVar[str] = '|= ip("{value}")'

    deferred_start: ClassVar[str] = ""
    deferred_separator: ClassVar[str] = " "
    deferred_only_query: ClassVar[str] = ""

    # Loki-specific functionality
    add_line_filters: bool = False
    case_insensitive: bool = True

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        add_line_filters: Union[bool, str] = False,
        case_insensitive: Union[bool, str] = True,
    ):
        super().__init__(processing_pipeline, collect_errors)
        self.last_processing_pipeline: Optional[
            ProcessingPipeline
        ] = processing_pipeline

        if isinstance(add_line_filters, bool):
            self.add_line_filters = add_line_filters
        else:
            self.add_line_filters = add_line_filters.lower() == "true"
        if isinstance(case_insensitive, bool):
            self.case_insensitive = case_insensitive
        else:
            self.case_insensitive = case_insensitive.lower() == "true"

    # Loki-specific functions
    # When converting values to regexes, we need to escape the string to prevent use of
    # non-wildcard metacharacters
    # As str equality is case-insensitive in Sigma, but LogQL regexes are case-sensitive,
    # we need to do the same for *ALL* string values and prepend with (?i)
    def convert_str_to_re(
        self, value: SigmaString, case_insensitive: bool = True
    ) -> SigmaRegularExpression:
        """Convert a SigmaString into a regular expression, replacing any
        wildcards with equivalent regular expression operators, and enforcing
        case-insensitive matching"""
        return SigmaRegularExpression(
            ("(?i)" if case_insensitive else "")
            + re.escape(str(value)).replace("\\?", ".").replace("\\*", ".*")
        )

    def select_log_parser(self, rule: SigmaRule) -> Union[str, LogQLLogParser]:
        """Select a relevant log parser based on common approaches to ingesting data into Loki.
        Currently defaults to logfmt, but will use the json parser for Windows, Azure and Zeek
        signatures."""
        if LokiCustomAttributes.PARSER.value in rule.custom_attributes:
            return rule.custom_attributes[LokiCustomAttributes.PARSER.value]
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
        if LokiCustomAttributes.LOGSOURCE_SELECTION.value in rule.custom_attributes:
            return rule.custom_attributes[
                LokiCustomAttributes.LOGSOURCE_SELECTION.value
            ]
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
                if isinstance(cond, ConditionOR):
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
                negated=getattr(expr, "negated", False),
                deftype=LogQLDeferredType.STR,
            )
        elif isinstance(
            expr.value, (SigmaString, SigmaNumber, SigmaBool)
        ) and not getattr(expr, "negated", False):
            return LogQLLineFilterInfo(
                value=str(expr.value),
                negated=getattr(expr, "negated", False),
                deftype=LogQLDeferredType.STR,
            )
        elif isinstance(expr.value, SigmaRegularExpression):
            # Could include field name if entries are logfmt and doesn't start with wildcard
            return LogQLLineFilterInfo(
                value=expr.value.regexp,
                negated=getattr(expr, "negated", False),
                deftype=LogQLDeferredType.REGEXP,
            )
        elif isinstance(expr.value, SigmaCIDRExpression):
            # Could include field name if entries are logfmt
            return LogQLLineFilterInfo(
                value=expr.value.cidr,
                negated=getattr(expr, "negated", False),
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
            (
                cand is None
                or getattr(cand, "negated", False)
                or cand.deftype is not LogQLDeferredType.STR
            )
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
        if isinstance(cond, ConditionFieldEqualsValueExpression):
            return self.convert_field_expression_to_line_filter(cond, log_parser)
        # AND clauses: any of the values could be true - so pick the longest one
        if isinstance(cond, ConditionAND):
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
        elif isinstance(cond, ConditionOR):
            candidates = [
                self.generate_candidate_line_filter(arg, log_parser)
                for arg in cond.args
            ]
            # The longest common substring of all the arguments is permissible as a
            # line filter, as every candidate must contain at least that string
            return self.find_longest_common_string_line_filter(candidates, log_parser)
        else:  # pragma: no cover
            # The above should cover all existing Sigma classes, but just in case...
            # (Helpful for spotting ConditionNOTs that somehow got through)
            raise SigmaError(
                f"Unhandled type by Loki backend: {str(cond.__class__.__name__)}"
            )

    def update_parsed_conditions(
        self, condition: ParentChainMixin, negated: bool = False
    ) -> ParentChainMixin:
        """Do a depth-first recursive search of the parsed items and update conditions
        to meet LogQL's structural requirements:

        - LogQL does not support wildcards in strings, so we convert them instead to
          regular expressions
        - LogQL does case sensitive searches by default, but Sigma strings are case
          insensitive, so to be fully spec compliant, we have to convert them into
          regular expressions with a leading (?i) flag
          - Can be disabled by setting the instance variable case_insensitive to False
        - LogQL does not support NOT operators, so we use De Morgan's law to push the
          negation down the tree (flipping ANDs and ORs and swapping operators, i.e.,
          = becomes !=, etc.)
        """
        if isinstance(
            condition,
            (ConditionFieldEqualsValueExpression, ConditionValueExpression),
        ):
            if (
                isinstance(condition.value, SigmaString)
                and (self.case_insensitive or condition.value.contains_special())
                and not isinstance(condition.value, SigmaCasedString)
            ):
                condition.value = self.convert_str_to_re(condition.value)
        if isinstance(condition, ConditionItem):
            if isinstance(condition, ConditionNOT):
                negated = not negated
                # Remove the ConditionNOT as the parent
                condition.args[0].parent = condition.parent
                return self.update_parsed_conditions(condition.args[0], negated)
            elif isinstance(condition, (ConditionAND, ConditionOR)):
                if negated:
                    if isinstance(condition, ConditionAND):
                        newcond = ConditionOR(condition.args, condition.source)
                    elif isinstance(condition, ConditionOR):
                        newcond = ConditionAND(condition.args, condition.source)
                    # Update the parent references to reflect the new structure
                    newcond.parent = condition.parent
                    for i in range(len(condition.args)):
                        condition.args[i].parent = newcond
                        condition.args[i] = self.update_parsed_conditions(
                            condition.args[i], negated
                        )
                    setattr(newcond, "negated", negated)
                    return newcond
                else:
                    for i in range(len(condition.args)):
                        condition.args[i] = self.update_parsed_conditions(
                            condition.args[i], negated
                        )
        # Record negation appropriately
        # NOTE: the negated property does not exist on the above classes,
        # so using setattr to set it dynamically
        setattr(condition, "negated", negated)
        return condition

    # Overriding Sigma TextQueryBackend functionality as necessary
    def convert_rule(
        self, rule: SigmaRule, output_format: Optional[str] = None
    ) -> List[str]:
        """Convert a single Sigma rule into one or more queries, based on the maximum
        estimated length of a generated query, and updating the parse tree
        appropriately.
        """
        attempted_conversion = False
        attempt_shortening = False
        error_state = "initialising"
        try:
            self.last_processing_pipeline = (
                self.backend_processing_pipeline
                + self.processing_pipeline
                + self.output_format_processing_pipeline[
                    output_format or self.default_format
                ]
            )

            error_state = "applying processing pipeline on"
            self.last_processing_pipeline.apply(rule)  # 1. Apply transformations
            states = [
                ConversionState(
                    processing_state=dict(self.last_processing_pipeline.state)
                )
                for _ in rule.detection.parsed_condition
            ]

            # 1.5. Apply Loki parse tree changes BEFORE attempting to convert a rule
            # When finalising a query from a condition, the index it is associated with
            # is the index of the parsed_condition from the rule detection. As this
            # code may partition one or more of these conditions into multiple
            # conditions, we explicitly associate them together here so the
            # relationship can be maintained throughout.
            conditions = [
                (index, self.update_parsed_conditions(cond.parsed))
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
                    (index, self.convert_condition(cond, states[index]))
                    for index, cond in conditions
                ]

                for index, query in queries:
                    if not states[index].has_deferred() and self.add_line_filters:
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
                                    states[index],
                                    self.convert_value_str(
                                        SigmaString(value), states[index]
                                    ),
                                )
                            elif def_type is LogQLDeferredType.REGEXP:
                                line_filter = LogQLDeferredUnboundRegexpExpression(
                                    states[index], value
                                )
                            elif def_type is LogQLDeferredType.CIDR:
                                line_filter = LogQLDeferredUnboundCIDRExpression(
                                    states[index], value
                                )
                            if negated:
                                line_filter.negate()

                    error_state = "finalizing query for"
                    final_query = self.finalize_query(
                        rule,
                        query,
                        index,
                        states[index],
                        output_format or self.default_format,
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
        """LogQL does not require any additional escaping for regular expressions if we
        can use the tilde character"""
        if "`" in r.regexp:
            return '"' + r.escape('"') + '"'
        return "`" + r.regexp + "`"

    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Implements OR'd unbounded conditions as a regex that combines the search terms
        with |s."""
        unbound_deferred_or = None
        for arg in cond.args:
            if isinstance(arg, ConditionValueExpression) and isinstance(
                arg.value, (SigmaString, SigmaRegularExpression)
            ):
                if unbound_deferred_or is None:
                    unbound_deferred_or = LogQLDeferredOrUnboundExpression(
                        state, [], "|~", self.case_insensitive
                    )
                    if getattr(cond, "negated", False):
                        unbound_deferred_or.negate()
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

    def convert_condition_field_eq_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Adjust the expression templates based on whether the condition is negated,
        prior to converting it. Not required for convert_condition_val, as they use
        deferred expressions, which use a different approach."""
        LogQLBackend.set_expression_templates(getattr(cond, "negated", False))
        return super().convert_condition_field_eq_val(cond, state)

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        if self.case_insensitive and len(cond.value) > 0:
            cond.value = self.convert_str_to_re(cond.value)
            return super().convert_condition_field_eq_val_re(cond, state)
        return super().convert_condition_field_eq_val_str(cond, state)

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """If the cased modifier is combined with startswith/endswith/contains
        modifiers, Sigma introduces wildcards that are then not handled correctly
        by Loki. So, in those cases, we convert the string to a regular expression."""
        if cond.value.contains_special():
            cond.value = self.convert_str_to_re(cond.value, False)
            return super().convert_condition_field_eq_val_re(cond, state)
        return super().convert_condition_field_eq_val_str_case_sensitive(cond, state)

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Converts all unbound wildcard conditions into regular expression queries,
        replacing wildcards with appropriate regex metacharacters."""
        expr = LogQLDeferredUnboundStrExpression(
            state, self.convert_value_str(cond.value, state)
        )
        if getattr(cond, "negated", False):
            expr.negate()
        return expr

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Convert unbound numeric queries into deferred line filters."""
        expr = LogQLDeferredUnboundStrExpression(state, cond.value)
        if getattr(cond, "negated", False):
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
        if getattr(cond, "negated", False):
            expr.negate()
        return expr

    def convert_condition_field_eq_expansion(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Select appropriate condition to join together field values and push down
        negation"""
        is_negated = getattr(cond, "negated", False)
        LogQLBackend.set_expression_templates(is_negated)
        exprs = [
            ConditionFieldEqualsValueExpression(cond.field, value)
            for value in cond.value.values
        ]
        # Fun fact: map(lamdba expr: setattr(expr, "negated", is_negated), exprs)
        # does nothing!
        for expr in exprs:
            setattr(expr, "negated", is_negated)
        if is_negated:
            cond = ConditionAND(exprs, cond.source)
        else:
            cond = ConditionOR(exprs, cond.source)
        return self.convert_condition(cond, state)

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
        if rule.author:
            ruler["annotations"]["author"] = rule.author
        if rule.level:
            ruler["labels"]["severity"] = rule.level.name.lower()  # type: ignore
        return ruler

    def finalize_output_ruler(self, queries: List[Dict[str, Any]]) -> str:
        """Produce a collection of alert queries bundled together in a single Loki ruler
        YAML format."""
        rules = {"groups": [{"name": "Sigma rules", "rules": queries}]}
        return dump(rules)
