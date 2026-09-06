"""Operational observability: metrics, and the endpoint that exposes them.

Structured logging and request correlation already existed - see
``app.core.logging_config`` and ``RequestContextMiddleware``, which have
carried a request id, the acting user and the operation on every line since
V2. What was missing was counts: how many requests, how slow, how many events
ingested, how many approvals refused. ``/metrics`` was even named in the
middleware's quiet-paths list, pointing at an endpoint that did not exist.

No dependency was added for this. ``prometheus_client`` would have been the
obvious choice and it is a good library, but the exposition format is a
hundred lines of text generation, this project ships no other runtime
dependency it does not use heavily, and a metrics library is not where a
security platform should spend its first unnecessary supply-chain edge.
"""
