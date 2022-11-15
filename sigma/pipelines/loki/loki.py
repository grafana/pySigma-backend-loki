from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline


def loki_log_parser() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Loki log parser pipeline",
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
