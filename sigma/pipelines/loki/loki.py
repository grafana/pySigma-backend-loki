from dataclasses import dataclass
from enum import Enum
from sigma.rule import SigmaRule
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import Transformation, FieldMappingTransformation


class LokiCustomAttrs(Enum):
    """The different custom attributes used by pipelines to store additional Loki-specific
    functionality."""

    PARSER = "loki_parser"
    LOGSOURCE_SELECTION = "logsource_loki_selection"


@dataclass
class SetLokiParserTransformation(Transformation):
    """Sets the relevant parser for the log data in the custom_attributes for an
    applicable rule."""

    parser: str

    def apply(self, pipeline: ProcessingPipeline, rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        rule.custom_attributes[LokiCustomAttrs.PARSER.value] = self.parser


@dataclass
class SetLokiStreamSelectionTransform(Transformation):
    """Sets the custom attribute `logsource_loki_selection` to define a more precise stream
    selector for Loki.

    Example selection:
        {job=`mylogs`,filename=~`.*[\\d]+.log$`}
    """

    selection: str

    def apply(self, pipeline: ProcessingPipeline, rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        rule.custom_attributes[
            LokiCustomAttrs.LOGSOURCE_SELECTION.value
        ] = self.selection


def loki_grafana_logfmt() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Loki Grafana logfmt field names",
        priority=20,
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


def loki_promtail_sysmon_message() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Loki Promtail Windows Sysmon Message Parser",
        priority=20,
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
                identifier="loki_promtail_sysmon_message_parser",
                transformation=SetLokiParserTransformation(
                    'json | label_format Message=`{{ .message | replace "\\\\" "\\\\\\\\" | replace "\\"" "\\\\\\"" }}` '  # noqa: E501
                    '| line_format `{{ regexReplaceAll "([^:]+): ?((?:[^\\\\r]*|$))(\\r\\n|$)" .Message "${1}=\\"${2}\\" "}}` '  # noqa: E501
                    "| logfmt"
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
