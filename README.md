![PyPI](https://img.shields.io/pypi/v/pysigma-backend-loki)
![Tests](https://github.com/grafana/pySigma-backend-loki/actions/workflows/test.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/grafana/pySigma-backend-loki/badge.svg?branch=main&t=lvM1Ns)](https://coveralls.io/github/grafana/pySigma-backend-loki?branch=main)

# pySigma Loki Backend

This is the Loki backend for pySigma. It provides the package `sigma.backends.loki` with the `LogQLBackend` class.

It supports the following output formats for Sigma rules:

* `default`: plain Loki LogQL queries
* `ruler`: creates Loki LogQL queries in the ruler (YAML) format for generating alerts

It also supports the following query formats for and categories of [Sigma Correlation rules](https://github.com/SigmaHQ/sigma-specification/blob/version_2/Sigma_meta_rules.md):
* `default` format using [LogQL metric queries](https://grafana.com/docs/loki/latest/query/metric_queries/):
  * `event_count`
  * `value_count`

It includes the following pipeline transformations in `sigma.pipelines.loki`:

* `SetCustomAttributeTransformation`: adds a specified custom attribute to a rule, which can be used to introduce a [stream selector](https://grafana.com/docs/loki/latest/logql/log_queries/#log-stream-selector) or [parser expression](https://grafana.com/docs/loki/latest/logql/log_queries/#parser-expression) into the generated query
  * The `LokiCustomAttributes` enum contains the relevant custom attribute names used by the backend

Further, it contains the processing pipelines in `sigma.pipelines.loki`:

* `loki_log_parser`: converts field names to logfmt labels used by Grafana
* `loki_promtail_sysmon`: parse and adjust field names for Windows sysmon data produced by promtail
  * Note: most rules lack the `sysmon` service tag, and hence this pipeline should be used in combination with the [generic sysmon pipeline](https://github.com/SigmaHQ/pySigma-pipeline-sysmon)
* `loki_okta_system_log`: parse the Okta System Log event json, adjusting field-names appropriately

When converting rules into queries, the backend has the following optional arguments:

* `add_line_filters` (boolean, default: `False`): if `True`, attempts to infer and add new line filters to queries without line filters, to [improve Loki query performance](https://grafana.com/docs/loki/latest/logql/log_queries/#line-filter-expression)
* `case_sensitive` (boolean, default: `False`): if `True`, defaults to generating case-sensitive query filters, instead of case-insensitive filters that [the Sigma specification expects](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#general), trading between Loki query performance and potentially missing data with unexpected casing
  * Note: if the generated query will be executed on Loki v2.8.2 or older, this argument **should** be set to `False`, as these versions of Loki may contain issues with case-insensitive filters, which cause such queries to fail to match desired data

This backend is currently maintained by:

* [Nick Moore](https://github.com/kelnage)
* [Mostafa Moradian](https://github.com/mostafa)

## Installation

To get started developing/testing pySigma-backend-loki, these steps may help you get started:

1. [Install poetry](https://python-poetry.org/docs/#installation)
2. Clone this repository and open a terminal/shell in the top-level directory
3. Run `poetry install` to install the Python dependencies
4. Run `poetry shell` to activate the poetry environment
5. Check it all works by running `poetry run pytest`
6. (Optional) If you wish to validate the generated rules using sigma\_backend\_tester.py, install
   [LogCLI](https://grafana.com/docs/loki/latest/tools/logcli/)
7. (Optional, but recommended) To enable the Git hooks, run the following command from the root directory of the repository:
```sh
git config --local core.hooksPath .githooks/
```

## Releasing

To release new versions of pySigma-backend-loki, we use GitHub actions to update PyPI. When the main branch is in state that is ready to release, the process is as follows:

1. Determine the correct version number using the [Semantic Versioning](https://semver.org/) methodology. All version numbers should be in the format `\d+\.\d+\.\d+(-[0-9A-Za-z-]+)?`
2. Update [pyproject.toml](https://github.com/grafana/pySigma-backend-loki/blob/main/pyproject.toml) with the new version number
3. Commit and push the change to GitHub, validate that the GitHub actions tests pass, and merge the PR into main
4. Checkout main and create a signed tag for the release, named the version number prefixed with a v, e.g., `git tag --sign --message="Release vX.X.X" vX.X.X`
5. Push the tag to GitHub, e.g., `git push --tags`, and validate that the release to the test instance of PyPI is successful
6. Run `poetry build` to produce distributable versions in `dist/`
7. Create a release in GitHub against the appropriate tag. If the version number starts with `v0`, or ends with `-alpha/beta` etc., mark it as a pre-release, and attach the distributable files to the release
8. Validate that the release to PyPI GitHub action is successful
9. If this release supports a new minor or major version of `pySigma`, do a pull request on the [pySigma-plugin-directory](https://github.com/SigmaHQ/pySigma-plugin-directory) to reflect that

## Work in progress

These features are currently either WIP or are planned to be implemented in the near future.

* Various processing pipelines for other applications and log sources
* Generating more accurate log stream selectors based on logsource
* Translate field names in Sigma signatures into relevant labels for Loki using pipelines

## Won't implement (probably)

These features are not easily supported by the backend, and hence are unlikely to be implemented.

* More complex keyword/line filter searches than ANDs of ORs
