import string
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Union

from sigma.types import SigmaString
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import (
    SigmaConfigurationError,
    SigmaFeatureNotSupportedByBackendError,
)
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    transformations,
    Transformation,
    AddFieldnamePrefixTransformation,
    FieldMappingTransformation,
)
from sigma.shared import sanitize_label_key, quote_string_value, join_or_values_re


class LokiCustomAttributes(Enum):
    """The different custom attributes used by pipelines to store additional Loki-specific
    functionality."""

    PARSER = "loki_parser"
    LOGSOURCE_SELECTION = "logsource_loki_selection"


@dataclass
class SetCustomAttributeTransformation(Transformation):
    """Sets an arbitrary custom attribute on a rule, that will be used during processing."""

    attribute: str
    value: Any

    def apply(
        self, pipeline: ProcessingPipeline, rule: Union[SigmaRule, SigmaCorrelationRule]
    ) -> None:
        super().apply(pipeline, rule)
        rule.custom_attributes[self.attribute] = self.value


def format_log_source_selector(field: str, value: Union[str, List[str]]) -> str:
    """Formats a string label name and either a single string or multiple strings into a valid LogQL
    stream selector query. This currently assumes that the label values are case-sensitive.
    """
    # TODO: replace log source placeholders
    if isinstance(value, str):
        # TODO: support regular expressions?
        string = SigmaString(value)
        return f"{sanitize_label_key(field)}={quote_string_value(string)}"
    elif isinstance(value, list):
        regex = join_or_values_re([SigmaString(s) for s in value], False)
        return f"{sanitize_label_key(field)}=~{regex}"
    raise SigmaConfigurationError(
        f"unable to format selector {value} for field {field}"
    )


@dataclass
class CustomLogSourceTransformation(Transformation):
    """Allow the definition of a log source selector using YAML structured data, including
    referencing log source and/or detection fields from the rule"""

    selection: Dict[str, Union[str, List[str]]]
    template: bool = False

    def apply(
        self, pipeline: ProcessingPipeline, rule: Union[SigmaRule, SigmaCorrelationRule]
    ):
        super().apply(pipeline, rule)
        if isinstance(rule, SigmaRule):
            selectors: List[str] = []
            refs: Dict[str, str] = {}
            for field, value in self.selection.items():
                if field.endswith("|fieldref"):
                    if isinstance(value, list):
                        raise SigmaConfigurationError(
                            f"fieldref custom log source transformation {field} "
                            "can only refer to a single field"
                        )
                    else:
                        refs[field.removesuffix("|fieldref")] = value
                else:
                    selectors.append(format_log_source_selector(field, value))
            if len(refs) > 0:
                plain = [
                    detection.to_plain()
                    for detection in rule.detection.detections.values()
                ]
                field_values: List[Dict[str, Union[str, int, None]]] = [
                    d for d in plain if isinstance(d, dict)
                ]
                if len(field_values) > 0:
                    for label, field_name in refs.items():
                        values: list[Union[str, int, None]] = []
                        for mapping in field_values:
                            if (
                                field_name in mapping
                                and mapping[field_name] is not None
                            ):
                                values.append(mapping[field_name])
                        if len(values) == 1:
                            selectors.append(
                                format_log_source_selector(label, str(values[0]))
                            )
                        elif len(values) > 1:
                            selectors.append(
                                format_log_source_selector(
                                    label, [str(v) for v in values]
                                )
                            )
            formatted_selectors = "{" + ",".join(selectors) + "}"
            if self.template:
                formatted_selectors = string.Template(formatted_selectors).safe_substitute(
                    category=rule.logsource.category,
                    product=rule.logsource.product,
                    service=rule.logsource.service,
                )
            rule.custom_attributes[
                LokiCustomAttributes.LOGSOURCE_SELECTION.value
            ] = formatted_selectors
        else:
            raise SigmaFeatureNotSupportedByBackendError(
                "custom log source transforms are not supported for Correlation rules"
            )


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
