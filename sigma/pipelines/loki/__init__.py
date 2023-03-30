from .loki import (
    LokiCustomAttributes,
    SetCustomAttributeTransformation,
    loki_grafana_logfmt,
    loki_promtail_sysmon_message,
)


pipelines = {
    "loki": loki_grafana_logfmt,
    "generic": loki_promtail_sysmon_message,
}
