# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **pySigma Loki Backend** — a plugin for the [pySigma](https://github.com/SigmaHQ/pySigma) framework that converts [Sigma](https://sigmahq.io/) security detection rules into [LogQL](https://grafana.com/docs/loki/latest/query/log-queries/) queries for Grafana Loki.

## Commands

```bash
# Install dependencies
poetry install

# Run all tests with coverage
poetry run pytest --cov=sigma --cov-report term --cov-report lcov:coverage.lcov -vv

# Run a single test file
poetry run pytest tests/test_backend_loki.py -vv

# Run a single test by name
poetry run pytest tests/test_backend_loki.py::test_name -vv

# Type checking
poetry run mypy --explicit-package-bases .

# Linting
poetry run ruff check .

# Formatting
poetry run ruff format .
```

Enable git hooks (recommended):
```bash
git config --local core.hooksPath .githooks/
```

## Architecture

### Key Source Files

- **`sigma/backends/loki/loki.py`** — Main `LogQLBackend` class (~1276 lines). Inherits from pySigma's `TextQueryBackend`. This is where Sigma conditions are converted to LogQL filter expressions.
- **`sigma/backends/loki/deferred.py`** — Deferred expression classes (line filters, label filters, CIDR, regex) that are appended after the stream selector and log parser in a query.
- **`sigma/shared.py`** — Shared utilities: string quoting/escaping, regex conversion, label key sanitization, negation operator maps.
- **`sigma/pipelines/loki/loki.py`** — Processing pipelines (`loki_grafana_logfmt`, `loki_promtail_sysmon`, `loki_okta_system_log`) and custom transformations (`SetCustomAttributeTransformation`, `CustomLogSourceTransformation`).

### LogQL Query Structure

A LogQL query produced by this backend has the form:
```
{stream_selector} | parser | line_filters | label_filters
```

The backend works by:
1. Selecting a log stream (`select_log_stream`) based on the rule's `logsource`
2. Selecting a log parser (`select_log_parser`) — JSON, LOGFMT, PATTERN, REGEXP, or UNPACK
3. Converting Sigma condition expressions into label filter expressions (field comparisons)
4. Optionally inferring line filters (`add_line_filters`) to improve query performance

### Negation Handling

Loki has no standalone NOT operator; negation is expressed at the comparison level (e.g., `!=` instead of `=`, `!~` instead of `=~`). The backend handles this via:
- `set_expression_templates(negated)` — swaps templates dynamically when inside a negated context
- `update_parsed_conditions` — tracks negation state during condition traversal
- `getattr(cond, "negated")` — checks negation on individual condition objects
- Negation operator maps in `sigma/shared.py`: `negated_line_filter_operator`, `negated_label_filter_operator`

Note: pySigma has a `convert_not_as_not_eq` option that may eventually replace this manual negation handling.

### Output Formats

- `default` — plain LogQL queries
- `ruler` — YAML format for Loki alerting rules (Loki Ruler API)
- `grafana_alerting` — Grafana Alerting provisioning YAML

Correlation rules (`event_count`, `value_count`) are supported via LogQL metric queries.

### Backend Options

- `add_line_filters` (bool, default `False`) — infer line filters for performance
- `case_sensitive` (bool, default `False`) — case-sensitive filters (faster but may miss data)
- `grafana_datasource_uid`, `grafana_folder`, `grafana_org_id`, `grafana_interval`, `grafana_contact_point`, `loki_group_by_field` — grafana_alerting format options

### Test Organization

Tests are in `tests/` and follow a consistent pattern using pytest fixtures:

```python
@pytest.fixture
def loki_backend():
    return LogQLBackend()

def test_example(loki_backend: LogQLBackend):
    assert loki_backend.convert(SigmaCollection.from_yaml("...")) == ["expected_query"]
```

Test files are split by feature area: negation, case sensitivity, line filters, field modifiers, field references, correlation rules (event_count, value_count), and pipelines.
