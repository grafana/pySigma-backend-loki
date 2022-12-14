from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.loki import (
    loki_grafana_logfmt,
    loki_promtail_sysmon_message,
)


def test_loki_grafana_pipeline():
    pipeline = loki_grafana_logfmt()
    backend = LogQLBackend(processing_pipeline=pipeline)
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                product: test
                service: test
            detection:
                sel:
                    c-uri: /a/path/to/something
                    sc-status: 200
                condition: sel
        """
    )
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == [
        '{job=~".+"} | logfmt | path=`/a/path/to/something` and status=200'
    ]


def test_windows_grafana_pipeline():
    pipeline = loki_promtail_sysmon_message()
    backend = LogQLBackend(processing_pipeline=pipeline)
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                product: windows
                service: sysmon
            detection:
                sel:
                    Image|endswith: .exe
                    EventID: 1
                condition: sel
        """
    )
    loki_rule = backend.convert(sigma_rule)
    assert loki_rule == [
        '{job=~"eventlog|winlog|windows|fluentbit.*"} | json '
        '| label_format Message=`{{ .message | replace "\\\\" "\\\\\\\\" | replace "\\"" "\\\\\\"" }}` '  # noqa: E501
        '| line_format `{{ regexReplaceAll "([^:]+): ?((?:[^\\\\r]*|$))(\\r\\n|$)" .Message "${1}=\\"${2}\\" "}}` '  # noqa: E501
        "| logfmt | Image=~`(?i).*\\.exe` and event_id=1"
    ]
