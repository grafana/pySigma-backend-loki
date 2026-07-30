import re
import string
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Union, Type

from sigma.conditions import (
    ConditionValueExpression,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
    ConditionOR,
    ConditionItem,
    ConditionType,
    ConditionAND,
    ConditionIdentifier,
    SigmaCondition,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import (
    SigmaFeatureNotSupportedByBackendError,
)
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    transformations,
    AddFieldnamePrefixTransformation,
    FieldMappingTransformation,
    PreprocessingTransformation,
)
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.types import (
    SigmaString,
    SigmaRegularExpression,
    SigmaFieldReference,
    SigmaType,
)

from sigma.shared import (
    sanitize_label_key,
    quote_string_value,
    join_or_values_re,
    escape_and_quote_re,
    convert_str_to_re,
)


class LokiCustomAttributes(Enum):
    """The different custom attributes used by pipelines to store additional Loki-specific
    functionality."""

    PARSER = "loki_parser"
    LOGSOURCE_SELECTION = "logsource_loki_selection"


@dataclass
class SetCustomAttributeTransformation(PreprocessingTransformation):
    """Sets an arbitrary custom attribute on a rule, that will be used during processing."""

    attribute: str
    value: Any

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        rule.custom_attributes[self.attribute] = self.value


def traverse_conditions(item: ConditionType):
    queue: List[
        Union[
            ConditionIdentifier,
            ConditionItem,
            ConditionFieldEqualsValueExpression,
            ConditionValueExpression,
            None,
        ]
    ] = [item]
    while len(queue) > 0:
        cond = queue.pop(0)
        if isinstance(cond, ConditionItem):
            queue.extend(cond.args)
        else:
            yield cond


def _remove_detection_from_condition(condition: str, det_name: str) -> str:
    """Remove a detection identifier (and its adjacent logical operator) from a condition string.

    Handles common patterns like 'sel and det', 'det and sel', 'sel and not det', etc.
    Does not support parenthesised sub-expressions or wildcard selectors (those are handled
    separately by removing the detection from the detections dict).
    """
    name_re = re.escape(det_name)
    term_re = rf"(?:not\s+)?{name_re}"

    # " and/or [not] det_name" — operator precedes the term
    result = re.sub(rf"\s+(?:and|or)\s+{term_re}\b", "", condition, flags=re.IGNORECASE)
    if result != condition:
        return result.strip()

    # "[not] det_name and/or " — operator follows the term
    result = re.sub(rf"\b{term_re}\s+(?:and|or)\s+", "", condition, flags=re.IGNORECASE)
    if result != condition:
        return result.strip()

    # term alone
    result = re.sub(rf"^\s*{term_re}\s*$", "", condition, flags=re.IGNORECASE)
    return result.strip()


def count_negated(classes: List[Type[Any]]) -> int:
    return len([neg for neg in classes if neg == ConditionNOT])


@dataclass
class CustomLogSourceTransformation(PreprocessingTransformation):
    """Allow the definition of a log source selector using YAML structured data, including
    referencing log source and/or detection fields from the rule"""

    selection: Dict[str, Union[str, List[str]]]
    case_insensitive: bool = False
    template: bool = False
    remove_from_detection: bool = False

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]):
        if isinstance(rule, SigmaRule):
            selectors: List[str] = []
            logsource_detections = SigmaDetection.from_definition(self.selection)
            conds = logsource_detections.postprocess(rule.detection)
            fields_set = set()
            detection_fields_consumed: set = set()
            args: List[
                Union[
                    ConditionIdentifier,
                    ConditionItem,
                    ConditionFieldEqualsValueExpression,
                    ConditionValueExpression,
                    None,
                ]
            ] = []
            if isinstance(conds, (ConditionOR, ConditionFieldEqualsValueExpression)):
                args.append(conds)
            elif isinstance(conds, ConditionAND):
                args.extend(conds.args)
            else:
                raise SigmaFeatureNotSupportedByBackendError(
                    "the custom log source selector only supports field equals value conditions"
                )
            for cond in args:
                field: Union[str, None] = None
                op: Union[str, None] = None
                value: Union[SigmaType, str, None] = None
                detection_field: Union[str, None] = None
                if isinstance(cond, ConditionValueExpression):
                    raise SigmaFeatureNotSupportedByBackendError(
                        "the custom log source selector only supports field equals value conditions"
                    )
                elif isinstance(cond, ConditionOR):
                    op = "=~"
                    values = []
                    for arg in cond.args:
                        if not isinstance(arg, ConditionFieldEqualsValueExpression):
                            raise SigmaFeatureNotSupportedByBackendError(
                                "the custom log source selector only supports a single nesting of "
                                "OR'd values"
                            )
                        if field is None:
                            field = arg.field
                        elif field != arg.field:
                            raise SigmaFeatureNotSupportedByBackendError(
                                "the custom log source selector only supports ORs on a single field"
                            )
                        if isinstance(arg.value, (SigmaString, SigmaRegularExpression)):
                            values.append(arg.value)
                    value = join_or_values_re(values, self.case_insensitive)
                elif isinstance(cond, ConditionFieldEqualsValueExpression):
                    field = cond.field
                    op = "="
                    value = cond.value
                    if not isinstance(
                        value,
                        (SigmaFieldReference, SigmaString, SigmaRegularExpression),
                    ):
                        raise SigmaFeatureNotSupportedByBackendError(
                            "the custom log selector pipeline only supports: string values, field "
                            "references and regular expressions"
                        )
                if field in fields_set:
                    raise SigmaFeatureNotSupportedByBackendError(
                        "the custom log source selector only allows one required value for a field"
                    )

                skip = False
                rule_conditions = []
                for parsed_conds in rule.detection.parsed_condition:
                    rule_conditions.extend(traverse_conditions(parsed_conds.parsed))  # type: ignore

                # Note: the order of these if statements is important and should be preserved
                if isinstance(value, SigmaFieldReference):
                    detection_field = value.field
                    values = []
                    negated = None
                    for item in rule_conditions:
                        if (
                            isinstance(item, ConditionFieldEqualsValueExpression)
                            and item.field == value.field
                            and isinstance(item.value, (SigmaString, SigmaRegularExpression))
                        ):
                            classes = item.parent_chain_condition_classes()
                            new_negated = count_negated(classes) % 2 == 1
                            if negated is not None and negated != new_negated:
                                # Skipping fields refs with both negated and un-negated values
                                skip = True
                            else:
                                negated = new_negated
                            values.append(item.value)
                    if len(values) == 0 or skip:
                        continue
                    if len(values) == 1 and isinstance(values[0], SigmaString):
                        if negated:
                            op = "!="
                        value = values[0]
                    else:
                        op = "=~"
                        if negated:
                            op = "!~"
                        value = join_or_values_re(values, self.case_insensitive)
                if isinstance(value, SigmaString):
                    if value.contains_special():
                        value = convert_str_to_re(value, self.case_insensitive, False)
                    else:
                        value = quote_string_value(value)
                # Not elif, as if the value was a string containing wildcards, it is now a RegEx
                if isinstance(value, SigmaRegularExpression):
                    op = "=~"
                    value = escape_and_quote_re(value)
                if field and op and value:
                    fields_set.add(field)
                    if detection_field is not None:
                        detection_fields_consumed.add(detection_field)
                    selectors.append(f"{sanitize_label_key(field)}{op}{value}")
            formatted_selectors = "{" + ",".join(selectors) + "}"
            if self.template:
                formatted_selectors = string.Template(formatted_selectors).safe_substitute(
                    category=rule.logsource.category,
                    product=rule.logsource.product,
                    service=rule.logsource.service,
                )
            rule.custom_attributes[LokiCustomAttributes.LOGSOURCE_SELECTION.value] = (
                formatted_selectors
            )
            if self.remove_from_detection and detection_fields_consumed:
                self._remove_fields_from_detection(rule, detection_fields_consumed)
            super().apply(rule)
        else:
            if rule.rules:
                for ruleref in rule.rules:
                    self.apply(ruleref.rule)

    def _remove_fields_from_detection(self, rule: SigmaRule, fields_to_remove: set) -> None:
        """Remove SigmaDetectionItems for consumed fields from rule.detection.

        For each detection group, items whose field is in fields_to_remove are dropped.
        If all items in a group are removed, the group is deleted from rule.detection.detections
        and all condition strings are updated to remove references to that group name — unless
        doing so would leave a condition string empty, in which case the group is left intact.
        """
        # Separate groups into those that become empty vs those that are only partially pruned
        groups_to_empty: List[str] = []
        groups_partial: Dict[str, list] = {}

        for det_name, detection in rule.detection.detections.items():
            new_items = [
                item
                for item in detection.detection_items
                if not (isinstance(item, SigmaDetectionItem) and item.field in fields_to_remove)
            ]
            if len(new_items) == 0:
                groups_to_empty.append(det_name)
            elif len(new_items) < len(detection.detection_items):
                groups_partial[det_name] = new_items

        # Apply partial pruning immediately — these groups stay in the detection
        for det_name, new_items in groups_partial.items():
            rule.detection.detections[det_name].detection_items = new_items

        # For groups that would become completely empty, only remove them when it is safe to do so
        # (i.e. the condition strings remain non-empty after the reference is dropped)
        safe_to_remove: List[str] = []
        for det_name in groups_to_empty:
            updated_conditions = []
            safe = True
            for cond_str in rule.detection.condition:
                new_cond = _remove_detection_from_condition(cond_str, det_name)
                if new_cond == "":
                    safe = False
                    break
                updated_conditions.append(new_cond)
            if safe:
                safe_to_remove.append(det_name)

        if safe_to_remove:
            for det_name in safe_to_remove:
                del rule.detection.detections[det_name]
            new_conditions = list(rule.detection.condition)
            for det_name in safe_to_remove:
                new_conditions = [
                    _remove_detection_from_condition(c, det_name) for c in new_conditions
                ]
            rule.detection.condition = new_conditions
            rule.detection.parsed_condition = [
                SigmaCondition(cond, rule.detection, rule.detection.source)
                for cond in rule.detection.condition
            ]


# Update pySigma transformations to include the above
# mypy type: ignore required due to incorrect type annotation on the transformations dict
transformations["set_custom_attribute"] = SetCustomAttributeTransformation  # type: ignore
transformations["set_custom_log_source"] = CustomLogSourceTransformation  # type: ignore


def loki_grafana_logfmt() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Loki Grafana logfmt field names",
        priority=20,
        allowed_backends=frozenset({"loki"}),
        items=[
            ProcessingItem(
                identifier="loki_grafana_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "ClientIP": "remote_addr",
                        "Endpoint": "path",
                        "User": "uname",
                        "c-ip": "remote_addr",
                        "c-uri": "path",
                        "cs-uri-query": "path",
                        "client_ip": "remote_addr",
                        "cs-method": "method",
                        "sc-status": "status",
                    }
                ),
            )
        ],
    )


def loki_promtail_sysmon() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Loki Promtail Windows Sysmon Message Parser",
        priority=20,
        allowed_backends=frozenset({"loki"}),
        items=[
            ProcessingItem(
                identifier="loki_promtail_sysmon_field_mapping",
                # Using the fieldnames in loki/clients/pkg/promtail/targets/windows/format.go
                transformation=FieldMappingTransformation(
                    {
                        "Source": "source",
                        "Channel": "channel",
                        "Computer": "computer",
                        "EventID": "event_id",
                        "Version": "version",
                        "Level": "level",
                        "Task": "task",
                        "Opcode": "opCode",
                        "LevelText": "levelText",
                        "TaskText": "taskText",
                        "OpcodeText": "opCodeText",
                        "Keywords": "keywords",
                        "TimeCreated": "timeCreated",
                        "EventRecordID": "eventRecordID",
                        "Correlation": "correlation",
                        "Execution": "execution",
                        "Security": "security",
                        "UserData": "user_data",
                        "EventData": "event_data",
                        "Message": "message",
                    }
                ),
            ),
            ProcessingItem(
                identifier="loki_promtail_sysmon_parser",
                transformation=SetCustomAttributeTransformation(
                    attribute=LokiCustomAttributes.PARSER.value,
                    value='json | label_format Message=`{{ .message | replace "\\\\" "\\\\\\\\" | replace "\\"" "\\\\\\"" }}` '  # noqa: E501
                    '| line_format `{{ regexReplaceAll "([^:]+): ?((?:[^\\\\r]*|$))(\\r\\n|$)" .Message "${1}=\\"${2}\\" "}}` '  # noqa: E501
                    "| logfmt",
                ),
                rule_conditions=[
                    LogsourceCondition(
                        product="windows",
                        service="sysmon",
                    )
                ],
            ),
        ],
    )


def loki_okta_system_log() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Loki Okta System Log json",
        priority=20,
        allowed_backends=frozenset({"loki"}),
        items=[
            ProcessingItem(
                identifier="loki_okta_event_json_formatter",
                transformation=SetCustomAttributeTransformation(
                    attribute=LokiCustomAttributes.PARSER.value,
                    value="json",
                ),
                rule_conditions=[
                    LogsourceCondition(
                        product="okta",
                        service="okta",
                    )
                ],
            ),
            ProcessingItem(
                identifier="loki_okta_field_name_mapping",
                # Transform event fields names that should be camelCase
                # See https://developer.okta.com/docs/reference/api/system-log/#logevent-object-annotated-example  # noqa: E501
                transformation=FieldMappingTransformation(
                    {
                        v.lower().replace("_", "."): v
                        for v in [
                            "eventType",
                            "legacyEventType",
                            "displayMessage",
                            "actor_alternateId",
                            "actor_displayName",
                            "client_userAgent_rawUserAgent",
                            "client_userAgent_os",
                            "client_userAgent_browser",
                            "client_geographicalContext_geolocation_lat",
                            "client_geographicalContext_geolocation_lon",
                            "client_geographicalContext_city",
                            "client_geographicalContext_state",
                            "client_geographicalContext_country",
                            "client_geographicalContext_postalCode",
                            "client_ipAddress",
                            "debugContext_debugData_requestUri",
                            "debugContext_debugData_originalPrincipal_id",
                            "debugContext_debugData_originalPrincipal_type",
                            "debugContext_debugData_originalPrincipal_alternateId",
                            "debugContext_debugData_originalPrincipal_displayName",
                            "debugContext_debugData_behaviors",
                            "debugContext_debugData_logOnlySecurityData",
                            "authenticationContext_authenticationProvider",
                            "authenticationContext_authenticationStep",
                            "authenticationContext_credentialProvider",
                            "authenticationContext_credentialType",
                            "authenticationContext_issuer_id",
                            "authenticationContext_issuer_type",
                            "authenticationContext_externalSessionId",
                            "authenticationContext_interface",
                            "securityContext_asNumber",
                            "securityContext_asOrg",
                            "securityContext_isp",
                            "securityContext_domain",
                            "securityContext_isProxy",
                            "target_alternateId",
                            "target_displayName",
                            "target_detailEntry",
                        ]
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(
                        product="okta",
                        service="okta",
                    )
                ],
            ),
            ProcessingItem(
                identifier="loki_okta_field_event_prefix",
                transformation=AddFieldnamePrefixTransformation("event_"),
                rule_conditions=[
                    LogsourceCondition(
                        product="okta",
                        service="okta",
                    )
                ],
            ),
        ],
    )
