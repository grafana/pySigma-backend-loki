from .loki import (
    LokiCustomAttributes,
    SetCustomAttributeTransformation,
    loki_grafana_logfmt,
    loki_promtail_sysmon_message,
    loki_okta_system_log_json,
)

__all__ = (
    "LokiCustomAttributes",
    "SetCustomAttributeTransformation",
    "loki_grafana_logfmt",
    "loki_promtail_sysmon_message",
    "loki_okta_system_log_json",
)

pipelines = {
    "loki_grafana_logfmt": loki_grafana_logfmt,
    "loki_promtail_sysmon": loki_promtail_sysmon_message,
    "loki_okta_system_log": loki_okta_system_log_json,
}
