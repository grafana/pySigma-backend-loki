from .loki import (
    CustomLogSourceTransformation,
    LokiCustomAttributes,
    SetCustomAttributeTransformation,
    loki_grafana_logfmt,
    loki_okta_system_log,
    loki_promtail_sysmon,
)

__all__ = (
    "CustomLogSourceTransformation",
    "LokiCustomAttributes",
    "SetCustomAttributeTransformation",
    "loki_grafana_logfmt",
    "loki_okta_system_log",
    "loki_promtail_sysmon",
)

pipelines = {
    "loki_grafana_logfmt": loki_grafana_logfmt,
    "loki_promtail_sysmon": loki_promtail_sysmon,
    "loki_okta_system_log": loki_okta_system_log,
}
