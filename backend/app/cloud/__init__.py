"""Cloud security posture.

**Nothing in this package talks to a cloud provider.** There is no SDK, no
credential handling and no network call anywhere in it, and Phase G did not add
one. Findings come from fixture files on disk and every record is flagged
``is_simulated``.

That is the same position V7 took for ``CloudTrailFileSource``, and for the same
reason: an AWS account, credentials and a configured trail do not exist in this
environment, and manufacturing a "validated cloud integration" without them
would be a claim the project cannot support. What a fixture-backed posture
scanner *can* do honestly is exercise the whole path - resource identity,
finding storage, incident correlation, evidence provenance - so that replacing
the scanner with a real one later changes one class and nothing else.
"""
