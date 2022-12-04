from dataclasses import dataclass
from sigma.rule import SigmaRule
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import Transformation, FieldMappingTransformation


@dataclass
class SetLokiParserTransformation(Transformation):
    """Sets the relevant parser for the log data in the custom_attributes for an
    applicable rule."""

    parser: str

    def apply(self, pipeline: ProcessingPipeline, rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        rule.custom_attributes["loki_parser"] = self.parser


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
                        "client_ip": "remote_addr",
                        "cs-method": "method",
                        "sc-status": "status",
                    }
                ),
            )
        ],
    )


def loki_windows_sysmon_message_parser() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Loki Windows Sysmon Message Parser",
        priority=20,
        items=[
            ProcessingItem(
                identifier="loki_sysmon_message_parsing",
                transformation=SetLokiParserTransformation(
                    "json"
                    '| label_format Message=`{{ .message | replace "\\" "\\\\" | replace """ "\\"" }}`'  # noqa: E501
                    '| line_format `{{ regexReplaceAll "([^:]+): ?((?:[^\\r]*|$))(\r\n|$)" .Message "${1}="${2}" "}}`'  # noqa: E501
                    "| logfmt"
                ),
                rule_conditions=[
                    LogsourceCondition(
                        product="windows",
                        service="sysmon",
                    )
                ],
            )
        ],
    )
