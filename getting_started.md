# Getting Started

This guide assumes you have:
* One or more systems that are generating **log data**
* One or more [Sigma rules](https://github.com/SigmaHQ/sigma/tree/master/rules) that you wish identify in that log data through **queries**
* (Optionally) One of more Sigma rules that you want to receive **alerts** for when it matches incoming log entries (WIP)

## Grafana Loki set-up

1. Install, configure and start [Grafana](https://grafana.com/docs/grafana/latest/#installing-grafana) and [Grafana Loki](https://grafana.com/docs/loki/latest/installation/)
   * Ensure that your Grafana instance and Loki instances are connected, and that Loki is configured as a data source
   * Don't want to host these yourself? Try [Grafana Cloud](https://grafana.com/docs/grafana-cloud/quickstart/)
2. Install [Promtail](https://grafana.com/docs/loki/latest/clients/promtail/installation/) and [configure it](https://grafana.com/docs/loki/latest/clients/promtail/configuration/) to scrape the log data from the target system and send it on to your Loki instance
   * If you are using Grafana Cloud, you can automatically generate a [Promtail configuration](https://grafana.com/docs/grafana-cloud/data-configuration/logs/collect-logs-with-promtail/), adjusting the `scrape_configs` stanza to reflect the target system
3. Start Promtail, wait a minute or two, and validate that the expected log data is being received
   1. In Grafana, go to the **Explore** page (the compass icon on the left-hand menu)
   2. Ensure your Loki instance is selected in the top-left corner
   3. Use the Label filters pull-downs to see the relevant labels that are being sent to Loki and their respective values
   4. Select a relevant label and value, and click on the **Run query** button in the top-right corner
   5. Check that any logs come back and they match the format you expected

## Sigma set-up

1. Ensure you have the following installed:
   * Git
   * [Python 3](https://wiki.python.org/moin/BeginnersGuide/Download) (3.9 or newer, check with `python --version`)
2. Install the Sigma command line tool, e.g., by [following these instructions](https://sigmahq.io/docs/guide/getting-started.html)
3. Once installed, install the Loki backend:
```
sigma plugin install loki
```

## Rule conversion - queries

With both Loki and Sigma setup, you can start converting Sigma rules into Loki queries. Use git to clone the [Sigma rules repository](https://github.com/SigmaHQ/sigma/):
```
git clone https://github.com/SigmaHQ/sigma.git
```

To convert a specific rule into a Loki query, you use the `sigma convert` command, with arguments telling it that you want to produce a Loki query, what file(s) to convert, and (optionally) providing one or more pipelines to adjust the rule to make sure it works correctly for your data. For example:
```
sigma convert -t loki sigma/rules/web/web_cve_2021_43798_grafana.yml # this generated query will likely not work!
```

The above converts a rule designed to detect an old vulnerability in Grafana into a Loki query, using the field names defined in the rule. However, the Grafana logs stored within Loki will likely not match the fields used by Sigma rules. Hence you need to use the `loki_grafana_logfmt` pipeline to make the query work:
```
sigma convert -t loki sigma/rules/web/web_cve_2021_43798_grafana.yml -p loki_grafana_logfmt
```

A similar process is used when querying Windows System Monitor (sysmon) event data (such as the rules in sigma/rules/windows/sysmon/). Assuming you are [using Promtail](https://grafana.com/docs/loki/latest/clients/promtail/configuration/#windows_events) to collect the sysmon logs, you will need to combine two pipelines; `sysmon` and `loki_promtail_sysmon`. This command will convert all those sysmon rules into queries:
```
sigma convert -t loki sigma/rules/windows/sysmon/ -p sysmon -p loki_promtail_sysmon
```

The sigma-cli tool does not support rules that include deprecated Sigma functionality - use the `-s` flag to ignore those rules when converting multiple rule files.

You will likely need to ingest a wider range of log data than the two examples shown above - [contributions of or suggestions for new pipelines](https://github.com/grafana/pySigma-backend-loki/issues) are more than welcome.

## Rule conversion - alerts

Coming soon!
