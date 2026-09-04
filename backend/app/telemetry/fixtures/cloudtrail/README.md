# CloudTrail fixtures — SIMULATED

Hand-written records in the public AWS CloudTrail record schema. **None of this
came from a real AWS account.** No credentials were used, no API was called, and
nothing here is evidence about real cloud activity.

They exist so `CloudTrailFileSource` can exercise the whole path — source →
adapter → canonical event → normalizer → feature extraction → detection —
locally and deterministically, without needing an AWS account.

Account id `123456789012` and the `203.0.113.0/24`, `198.51.100.0/24` addresses
are the RFC 5737 / AWS documentation reserved ranges, chosen so that nothing
here can resolve to a real principal or host.
