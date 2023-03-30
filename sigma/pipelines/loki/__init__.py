from .loki import (
    LokiCustomAttributes,
    SetCustomAttributeTransformation,
    loki_grafana_logfmt,
    loki_promtail_sysmon_message,
)

__all__ = (
    "LokiCustomAttributes",
    "SetCustomAttributeTransformation",
    "loki_grafana_logfmt",
    "loki_promtail_sysmon_message",
)

pipelines = {
    "loki_grafana_logfmt": loki_grafana_logfmt,
    "loki_promtail_sysmon": loki_promtail_sysmon_message,
}
