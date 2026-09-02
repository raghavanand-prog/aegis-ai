"""Indicator validation.

Indicator values originate in telemetry, which is untrusted input. They end up
in an outbound HTTP request path, so they are validated against a strict
allowlist before any provider sees them - not escaped, not sanitised,
*validated*: an indicator that does not match its type's grammar is refused.

The specific risk this closes is SSRF through enrichment. Without it, a crafted
log line carrying a "domain" of ``169.254.169.254/latest/meta-data`` or
``localhost:8000/api/v1/...`` would have the backend make that request on the
attacker's behalf, from inside the network, with whatever credentials the
provider client happens to hold.

Private, loopback, link-local and reserved addresses are also refused for a
second reason: sending internal addressing to a third-party reputation service
leaks the estate's topology, and no provider has anything useful to say about
10.0.0.5 anyway.

Documentation ranges (RFC 5737, RFC 3849) get their own rejection and their own
message. AEGISX's synthetic generator uses them for "external" addresses, so
without this the demo stream would send a stream of fabricated addresses to a
real reputation API - meaningless verdicts, real quota. It also means threat
intelligence stays quiet on purely synthetic telemetry, which is documented in
docs/threat-intelligence.md rather than left as a surprise.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

MAX_INDICATOR_LENGTH = 512

# Labels of 1-63 chars, a TLD of at least two letters. Deliberately strict.
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)
_HASH = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


class InvalidIndicator(ValueError):
    """Raised when an indicator cannot safely be sent to a provider."""


#: RFC 5737 / RFC 3849 documentation ranges. The synthetic telemetry generator
#: uses these for "outside the estate" precisely because they are never routed,
#: so they are refused for their own reason rather than being lumped in with
#: internal addressing: sending a fabricated address to a real reputation
#: service produces a meaningless verdict and burns quota.
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _reject_reserved_ip(address: str) -> None:
    parsed = ipaddress.ip_address(address)

    for network in _DOCUMENTATION_NETWORKS:
        if parsed.version == network.version and parsed in network:
            raise InvalidIndicator(
                f"{address} is in a documentation range (RFC 5737/3849). AEGISX's "
                "synthetic telemetry uses these addresses, and looking one up would "
                "ask a real provider about an address that does not exist."
            )

    if (
        parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_unspecified
    ):
        raise InvalidIndicator(
            f"{address} is a loopback, link-local or multicast address; "
            "it is never sent to an external provider"
        )

    if parsed.is_private or parsed.is_reserved:
        raise InvalidIndicator(
            f"{address} is a private or reserved address. Sending internal "
            "addressing to a third party leaks the estate's topology, and no "
            "provider has anything useful to say about it."
        )


def validate(ioc_type: str, value: str) -> str:
    """Return the normalized indicator, or raise :class:`InvalidIndicator`."""
    if not value or not isinstance(value, str):
        raise InvalidIndicator("Empty indicator")

    candidate = value.strip()
    if len(candidate) > MAX_INDICATOR_LENGTH:
        raise InvalidIndicator("Indicator exceeds the maximum length")
    if any(ch.isspace() or ord(ch) < 32 for ch in candidate):
        raise InvalidIndicator("Indicator contains whitespace or control characters")

    kind = ioc_type.strip().lower()

    if kind == "ip":
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise InvalidIndicator(f"{candidate!r} is not a valid IP address") from exc
        _reject_reserved_ip(candidate)
        return str(parsed)

    if kind == "domain":
        lowered = candidate.lower().rstrip(".")
        # A bare address dressed up as a domain must go through the IP rules.
        try:
            ipaddress.ip_address(lowered)
        except ValueError:
            pass
        else:
            _reject_reserved_ip(lowered)
            return lowered
        if not _DOMAIN.match(lowered):
            raise InvalidIndicator(f"{candidate!r} is not a valid domain name")
        return lowered

    if kind == "url":
        parts = urlsplit(candidate)
        if parts.scheme not in {"http", "https"}:
            raise InvalidIndicator("Only http and https URLs are looked up")
        if not parts.hostname:
            raise InvalidIndicator("URL has no host")
        host = parts.hostname.lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not _DOMAIN.match(host):
                raise InvalidIndicator(f"{host!r} is not a valid URL host") from None
        else:
            _reject_reserved_ip(host)
        return candidate

    if kind == "hash":
        if not _HASH.match(candidate):
            raise InvalidIndicator(
                "Hash must be 32, 40 or 64 hexadecimal characters (MD5/SHA-1/SHA-256)"
            )
        return candidate.lower()

    raise InvalidIndicator(f"Indicator type {ioc_type!r} is not looked up externally")


def is_valid(ioc_type: str, value: str) -> bool:
    try:
        validate(ioc_type, value)
    except InvalidIndicator:
        return False
    return True
