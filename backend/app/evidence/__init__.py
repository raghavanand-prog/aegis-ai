"""Investigation evidence.

A provider-neutral view of everything AEGISX knows about an incident, with the
provenance of each piece attached to it. See :mod:`app.evidence.models` for the
contract and :mod:`app.evidence.service` for how a set is assembled.
"""

from app.evidence import registry

__all__ = ["registry"]
