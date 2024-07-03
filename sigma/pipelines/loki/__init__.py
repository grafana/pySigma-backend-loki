from .loki import (
    LokiCustomAttributes,
    SetCustomAttributeTransformation,
    CustomLogSourceTransformation,
    loki_grafana_logfmt,
    loki_promtail_sysmon,
    loki_okta_system_log,
)

__all__ = (
    "LokiCustomAttributes",
    "SetCustomAttributeTransformation",
    "CustomLogSourceTransformation",
    "loki_grafana_logfmt",
    "loki_promtail_sysmon",
    "loki_okta_system_log",
)

pipelines = {
    "loki_grafana_logfmt": loki_grafana_logfmt,
    "loki_promtail_sysmon": loki_promtail_sysmon,
    "loki_okta_system_log": loki_okta_system_log,
}
