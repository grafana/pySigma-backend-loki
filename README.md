![Tests](https://github.com/kelnage/pySigma-backend-loki/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/kelnage/246287f4de22321bb497c8ae34601c29/raw/kelnage-pySigma-backend-loki.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Loki Backend

This is the Loki backend for pySigma. It provides the package `sigma.backends.loki` with the `LogQLBackend` class.

It supports the following output formats:

* default: plain Loki LogQL queries
* ruler: creates Loki LogQL queries in the ruler (YAML) format for generating alerts

Further, it contains the processing pipelines in `sigma.pipelines.loki`:

* loki\_log\_parser: converts field names to logfmt labels used by Grafana

This backend is currently maintained by:

* [Nick Moore](https://github.com/kelnage/)

## Installation

To get started developing/testing pySigma-backend-loki, these steps may help you get started:

1. [Install poetry](https://python-poetry.org/docs/#installation)
2. Clone this repository and open a terminal/shell in the top-level directory
3. Run `poetry install` to install the Python dependencies
4. Run `poetry shell` to activate the poetry environment
5. Check it all works by running `poetry run pytest`
6. (Optional) If you wish to validate the generated rules using sigma\_backend\_tester.py, install
   [LogCLI](https://grafana.com/docs/loki/latest/tools/logcli/)

## Work in progress

These features are currently either WIP or are planned to be implemented in the near future.

* Various processing pipelines for other applications and log sources
* Some generated queries are too large for Loki - such rules could be factored into multiple queries
* Analysing a rule's searches to identify line filters that could improve the query performance
* Generating more accurate log stream selectors based on logsource
* Translate field names in Sigma signatures into relevant labels for Loki using pipelines

## Won't implement (probably)

These features are not easily supported by the backend, and hence are unlikely to be implemented.

*  More complex keyword/line filter searches than ANDs of ORs

