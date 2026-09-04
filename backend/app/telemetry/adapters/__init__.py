"""The adapter registry: which parser reads which source.

Resolution is by source display name first, then by telemetry class. Both were
true in V6 as well - this module makes the second step *visible*.

**On the fallback.** V6's ``FALLBACK_BY_TYPE`` silently handed an unrecognised
ENDPOINT source to the Sysmon mapper. That is not obviously wrong (a new EDR
product does look broadly like the ones already mapped) but it was invisible: an
unknown vendor produced plausible, confidently-shaped, quite possibly incorrect
events and nothing anywhere recorded that a foreign parser had read them. The
fallback is kept, because refusing every unregistered source would break the
existing collector contract, but resolution is now recorded on every event as
``exact`` or ``fallback``.
"""

from __future__ import annotations

from app.models.enums import SourceType
from app.telemetry.adapters.base import AdapterError, TelemetryAdapter
from app.telemetry.adapters.cloudtrail import CloudTrailAdapter
from app.telemetry.adapters.defender import DefenderAdapter
from app.telemetry.adapters.dns import DnsAdapter
from app.telemetry.adapters.edr import EdrAdapter
from app.telemetry.adapters.entra import EntraAdapter
from app.telemetry.adapters.firewall import FirewallAdapter
from app.telemetry.adapters.linux import LinuxAdapter
from app.telemetry.adapters.sysmon import SysmonAdapter

#: Registration order is also fallback precedence within a telemetry class:
#: the first adapter registered for a class is the one an unknown source of that
#: class falls back to. It matches V6's FALLBACK_BY_TYPE exactly.
ADAPTERS: tuple[TelemetryAdapter, ...] = (
    SysmonAdapter(),
    DefenderAdapter(),
    EntraAdapter(),
    FirewallAdapter(),
    DnsAdapter(),
    LinuxAdapter(),
    EdrAdapter(),
    CloudTrailAdapter(),
)

#: source display name -> adapter
BY_SOURCE_NAME: dict[str, TelemetryAdapter] = {
    name: adapter for adapter in ADAPTERS for name in adapter.source_names
}

#: telemetry class -> the adapter an unregistered source of that class gets.
BY_SOURCE_TYPE: dict[SourceType, TelemetryAdapter] = {}
for _adapter in ADAPTERS:
    if _adapter.fallback_for is not None:
        BY_SOURCE_TYPE.setdefault(_adapter.fallback_for, _adapter)


def resolve(source: str, source_type: SourceType) -> tuple[TelemetryAdapter, str]:
    """Return the adapter for a source and how it was chosen.

    Raises ``LookupError`` when neither the source nor its class is registered.
    The caller turns that into a ``NormalizationError``; the split keeps this
    module free of the normalizer's exception vocabulary.
    """
    from app.telemetry.canonical import RESOLUTION_EXACT, RESOLUTION_FALLBACK

    adapter = BY_SOURCE_NAME.get(source)
    if adapter is not None:
        return adapter, RESOLUTION_EXACT

    adapter = BY_SOURCE_TYPE.get(source_type)
    if adapter is not None:
        return adapter, RESOLUTION_FALLBACK

    raise LookupError(
        f"No telemetry adapter registered for source {source!r} and no fallback "
        f"for telemetry class {source_type.value!r}."
    )


def register(adapter: TelemetryAdapter, *, as_fallback: bool = False) -> None:
    """Add an adapter at runtime.

    Used by tests and by anything loading a source outside this package. A
    second adapter claiming a name already registered is refused: silently
    replacing one would change how every event from that source is parsed, and
    nothing would say so.
    """
    for name in adapter.source_names:
        if name in BY_SOURCE_NAME and BY_SOURCE_NAME[name] is not adapter:
            raise ValueError(
                f"An adapter is already registered for source {name!r}. Two "
                "parsers for one source would make the mapping depend on import "
                "order."
            )
        BY_SOURCE_NAME[name] = adapter
    if as_fallback and adapter.fallback_for is not None:
        BY_SOURCE_TYPE.setdefault(adapter.fallback_for, adapter)


__all__ = [
    "ADAPTERS",
    "BY_SOURCE_NAME",
    "BY_SOURCE_TYPE",
    "AdapterError",
    "TelemetryAdapter",
    "register",
    "resolve",
]
