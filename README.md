![Tests](https://github.com/kelnage/pySigma-backend-loki/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/kelnage/246287f4de22321bb497c8ae34601c29/raw/kelnage-pySigma-backend-loki.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Loki Backend

This is the Loki backend for pySigma. It provides the package `sigma.backends.loki` with the `LogQLBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.loki`:

* pipeline1: purpose
* pipeline2: purpose

It supports the following output formats:

* default: plain Loki LogQL queries
* ruler: creates Loki queries in the ruler format for generating alerts

This backend is currently maintained by:

* [Nick Moore](https://github.com/kelnage/)

