from dataclasses import dataclass
from enum import Enum
from typing import Any, List
from sigma.modifiers import modifier_mapping
from sigma.rule import SigmaRule, SigmaDetectionItem
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.exceptions import SigmaConfigurationError
from sigma.processing.transformations import (
    transformations,
    Transformation,
    DetectionItemTransformation,
    AddFieldnamePrefixTransformation,
    FieldMappingTransformation,
)


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

    def apply(self, pipeline: ProcessingPipeline, rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        rule.custom_attributes[self.attribute] = self.value


@dataclass
class AddModifiersTransformation(DetectionItemTransformation):
    """Adds modifier(s) (e.g., "contains", "endswith", etc.)  to existing field(s)."""

    modifiers: List[str]

    def __post_init__(self):
        for modifier in self.modifiers:
            if modifier not in modifier_mapping:
                raise SigmaConfigurationError(
                    f"The modifier '{self.modifiers}' is not a valid modifier"
                )

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> SigmaDetectionItem:
        modifier_classes = [modifier_mapping[mod] for mod in self.modifiers]
        previous_modifiers = detection_item.modifiers
        detection_item.modifiers = modifier_classes
        detection_item.apply_modifiers()
        detection_item.modifiers = previous_modifiers + modifier_classes
        return detection_item


# Update pySigma transformations to include the above
transformations["set_custom_attribute"] = SetCustomAttributeTransformation
transformations["add_modifiers"] = AddModifiersTransformation


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
                        v.lower(): v
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
