"""Cloud resource identity.

A posture finding is shown on an incident because the two concern the same
resource. That makes resource comparison a security boundary, not a
convenience: anything that can make two different resources compare equal is a
way to put one account's posture in front of another account's analyst.

So identity is **structural**. An ARN is parsed into its fields and the fields
are compared. It is never compared as a string, and a resource *name* - the one
field an attacker can influence - is never allowed to contribute to the account,
region or service the resource is understood to be in.

Only AWS ARNs are parsed today. Azure and GCP have their own identity formats
and neither is guessed at here: a resource this module cannot parse is
``None``, which matches nothing, rather than a partially-understood identity
that matches too much.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

#: Long enough for any real ARN, short enough that a hostile value cannot make
#: the regex engine the expensive part of ingestion.
MAX_ARN_LENGTH = 2048

#: AWS account ids are exactly twelve digits.
_ACCOUNT = re.compile(r"\A\d{12}\Z")

#: Regions are lowercase alphanumerics and hyphens. Anchored, because a region
#: is a field an ARN's later segments must not be able to reach into.
_REGION = re.compile(r"\A[a-z0-9-]{1,64}\Z")

#: Service namespaces are lowercase alphanumerics, hyphens and dots.
_SERVICE = re.compile(r"\A[a-z0-9.-]{1,64}\Z")


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


#: ARN partitions this understands. ``aws-cn`` and ``aws-us-gov`` are real and
#: deliberately absent: this project has no fixtures for either, and accepting
#: a partition it has never seen a record from would be a guess.
_PARTITIONS = {"aws"}


@dataclass(frozen=True, slots=True)
class ResourceRef:
    """One cloud resource, identified by its parts rather than its text."""

    provider: CloudProvider
    #: Owning account. Never taken from a resource name.
    account: str
    #: ``None`` for a global service such as IAM or S3. Absence, not ``""``:
    #: a resource in "the empty region" is not a thing.
    region: str | None
    service: str
    #: ``""`` when the ARN names a resource without a type, which is legal.
    resource_type: str
    resource_id: str

    @property
    def key(self) -> str:
        """A canonical string for indexing and equality in storage.

        Safe to compare as text *because* it is built from an already-parsed
        reference. Building one from raw input would reintroduce exactly the
        confusion this module exists to prevent.
        """
        return "|".join(
            (
                self.provider.value,
                self.account,
                self.region or "-",
                self.service,
                self.resource_type,
                self.resource_id,
            )
        )


def parse_arn(value: str | None) -> ResourceRef | None:
    """Read an AWS ARN, or return ``None``.

    Never raises. ARNs arrive inside telemetry, which is attacker-adjacent, and
    a parser that throws would let a malformed record stop an ingestion tick.
    """
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > MAX_ARN_LENGTH:
        return None

    # Exactly six segments: arn:partition:service:region:account:resource.
    # The resource segment keeps its own colons, which is why the split is
    # bounded - an unbounded split would let a resource name shift every
    # field left and land its own text in `account`.
    parts = value.split(":", 5)
    if len(parts) != 6:
        return None

    scheme, partition, service, region, account, resource = parts

    if scheme.lower() != "arn":
        return None
    if partition.lower() not in _PARTITIONS:
        return None

    # Case is folded on the fields the cloud itself treats as case-insensitive
    # and left alone on the resource, where two spellings are two resources.
    service = service.lower()
    region = region.lower()

    if not _SERVICE.match(service):
        return None
    if region and not _REGION.match(region):
        return None
    if not _ACCOUNT.match(account):
        # S3 and a few other global services omit the account entirely.
        if account != "":
            return None
    if not resource:
        return None

    resource_type, resource_id = _split_resource(resource)
    if not resource_id:
        return None

    return ResourceRef(
        provider=CloudProvider.AWS,
        account=account,
        region=region or None,
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
    )


def _split_resource(resource: str) -> tuple[str, str]:
    """Separate ``type/id``, ``type:id`` or a bare ``id``.

    Only the *first* separator divides them. An IAM path
    (``role/service-role/deploy``) is part of the name, so everything after the
    first separator is the id.
    """
    for separator in ("/", ":"):
        head, found, tail = resource.partition(separator)
        if found and tail:
            # Whichever separator appears first is the real one.
            other = "/" if separator == ":" else ":"
            other_index = resource.find(other)
            if other_index != -1 and other_index < len(head):
                continue
            return head, tail
    return "", resource


def same_resource(left: ResourceRef | None, right: ResourceRef | None) -> bool:
    """Whether two references are the same resource.

    ``None`` matches nothing, including another ``None``. Two resources AEGISX
    could not identify are not "the same unknown resource", and treating them
    as equal would attach every unparseable finding to every unparseable
    principal.
    """
    if left is None or right is None:
        return False
    return left == right
