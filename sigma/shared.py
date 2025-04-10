import re
from typing import Dict, List, Union
from sigma.types import (
    SigmaCasedString,
    SigmaString,
    SigmaRegularExpression,
    SpecialChars,
)


negated_line_filter_operator: Dict[str, str] = {
    "|=": "!=",
    "!=": "|=",
    "|~": "!~",
    "!~": "|~",
}

negated_label_filter_operator: Dict[str, str] = {
    "=": "!=",
    "==": "!=",
    "!=": "=",
    ">": "<=",
    ">=": "<",
    "<": ">=",
    "<=": ">",
}


def sanitize_label_key(key: str, isprefix: bool = True) -> str:
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
            (
                r
                if (r >= "a" and r <= "z")
                or (r >= "A" and r <= "Z")
                or r == "_"
                or (r >= "0" and r <= "9")
                else "_"
            )
            for r in key
        )
    )


def quote_string_value(s: SigmaString) -> str:
    """By default, use the tilde character to quote fields, which needs limited escaping.
    If the value contains a tilde character, use double quotes and apply more rigourous
    escaping."""
    quote = "`"
    if any([c == quote for c in str(s)]):
        quote = '"'
    # If our string doesn't contain any tilde characters
    if quote == "`":
        converted = s.convert()
    else:
        converted = s.convert(escape_char="\\", add_escaped='"\\')
    return quote + converted + quote


def convert_str_to_re(
    value: SigmaString,
    case_insensitive: bool = True,
    field_filter: bool = False,
) -> SigmaRegularExpression:
    """Convert a SigmaString into a regular expression, replacing any
    wildcards with equivalent regular expression operators, and enforcing
    case-insensitive matching"""
    return SigmaRegularExpression(
        ("(?i)" if case_insensitive else "")
        + (
            "^"
            if field_filter and not value.startswith(SpecialChars.WILDCARD_MULTI)
            else ""
        )
        + re.escape(str(value)).replace("\\?", ".").replace("\\*", ".*")
        + (
            "$"
            if field_filter and not value.endswith(SpecialChars.WILDCARD_MULTI)
            else ""
        )
    )


def escape_and_quote_re(r: SigmaRegularExpression, flag_prefix=True) -> str:
    """LogQL does not require any additional escaping for regular expressions if we
    can use the tilde character"""
    if "`" in r.regexp:
        return '"' + r.escape(('"',), flag_prefix=flag_prefix) + '"'
    return "`" + r.escape((), "", False, flag_prefix) + "`"  # type: ignore


def join_or_values_re(
    exprs: List[Union[SigmaString, SigmaRegularExpression]], case_insensitive: bool
) -> str:
    # This makes the regex case insensitive if any values are SigmaStrings
    # or if any of the regexes are case insensitive
    # TODO: can we make this more precise?
    case_insensitive = any(
        (
            isinstance(val, SigmaString)
            and case_insensitive
            and not isinstance(val, SigmaCasedString)
        )
        or (isinstance(val, SigmaRegularExpression) and val.regexp.startswith("(?i)"))
        for val in exprs
    )
    vals = [
        convert_str_to_re(val)
        if isinstance(val, SigmaString) and val.contains_special()
        else val
        for val in exprs
    ]
    or_value = "|".join(
        (
            (
                re.escape(str(val))
                if isinstance(val, SigmaString)
                else re.sub("^\\(\\?i\\)", "", val.regexp)
            )
            for val in vals
        )
    )
    if case_insensitive:
        or_value = "(?i)" + or_value
    if "`" in or_value:
        or_value = '"' + SigmaRegularExpression(or_value).escape(('"',)) + '"'
    else:
        or_value = "`" + or_value + "`"
    return or_value
