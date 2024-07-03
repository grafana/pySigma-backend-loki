import re
from typing import List, Union
from sigma.types import SigmaCasedString, SigmaString, SigmaRegularExpression


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
    or_value = "|".join(
        (
            (
                re.escape(str(val))
                if isinstance(val, SigmaString)
                else re.sub("^\\(\\?i\\)", "", val.regexp)
            )
            for val in exprs
        )
    )
    if case_insensitive:
        or_value = "(?i)" + or_value
    if "`" in or_value:
        or_value = '"' + SigmaRegularExpression(or_value).escape(('"',)) + '"'
    else:
        or_value = "`" + or_value + "`"
    return or_value
