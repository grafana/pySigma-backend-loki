from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ValueListPlaceholderTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

def loki_log_parser() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Loki log parser pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="loki_grafana_field_mapping",
                transformation=FieldMappingTransformation({
                    "ClientIP": "remote_addr",
                    "Endpoint": "path",
                    "User": "uname",
                    "c-ip": "remote_addr",
                    "c-uri": "path",
                    "client_ip": "remote_addr",
                    "cs-method": "method",
                    "sc-status": "status",
                })
            )
#             ProcessingItem(     # This is an example for processing items generated from the mapping above.
#                 identifier=f"loki_windows_{service}",
#                 transformation=AddConditionTransformation({ "source": source}),
#                 rule_conditions=[logsource_windows(service)],
#             )
#             for service, source in windows_logsource_mapping.items()
#         ] + [
#             ProcessingItem(     # Field mappings
#                 identifier="loki_field_mapping",
#                 transformation=FieldMappingTransformation({
#                     "EventID": "event_id",      # TODO: define your own field mappings
#                 })
#             )
        ],
    )
