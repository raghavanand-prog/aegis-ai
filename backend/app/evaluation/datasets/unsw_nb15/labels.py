"""Ground-truth label schema for UNSW-NB15.

The dataset ships two label columns: ``label`` (0/1) and ``attack_cat`` (the
attack family, empty for benign traffic). They agree exactly - across all
2,280,090 records there is no benign row carrying a category and no malicious
row missing one - so ``attack_cat`` is used as the category axis and ``label``
as the binary axis, and a disagreement between them is treated as a hard error
rather than resolved silently.

**What is normalized, and why.** The raw column is not clean: the same family
appears as ``"Fuzzers"``, ``" Fuzzers"`` and ``" Fuzzers "``, and
``"Backdoor"``/``"Backdoors"`` both occur. These are spelling and whitespace
variants of the nine families the dataset's authors documented, not distinct
classes, so they are folded together and the fold is recorded here in full.

**What is deliberately NOT done.** These categories are *not* mapped onto the
AEGISX :class:`~app.evaluation.labels.Label` enum. That enum describes the
endpoint/identity attack classes of the synthetic corpus; UNSW-NB15 describes
network-flow attack families. "Generic" (a cryptographic block-cipher attack)
and "Fuzzers" have no AEGISX counterpart, and inventing one would fabricate a
result. The two taxonomies stay separate and every report says which is in use.
"""

from __future__ import annotations

from app.evaluation.datasets.base import LabelSchema

BENIGN = "benign"

#: The nine attack families documented by Moustafa & Slay, lowercase.
ATTACK_CATEGORIES: tuple[str, ...] = (
    "analysis",
    "backdoor",
    "dos",
    "exploits",
    "fuzzers",
    "generic",
    "reconnaissance",
    "shellcode",
    "worms",
)

#: Every literal string observed in ``attack_cat``, mapped to its normalized
#: family. Built explicitly rather than by ``.strip().lower()`` so that a value
#: this project has never seen is refused instead of being coerced into a class
#: it may not belong to.
RAW_LABEL_MAP: dict[str, str] = {
    # The benign class is a NULL in the source column, read as "" by the loader.
    "": BENIGN,
    "Analysis": "analysis",
    "Backdoor": "backdoor",
    "Backdoors": "backdoor",
    "DoS": "dos",
    "Exploits": "exploits",
    " Fuzzers": "fuzzers",
    " Fuzzers ": "fuzzers",
    "Generic": "generic",
    "Reconnaissance": "reconnaissance",
    " Reconnaissance ": "reconnaissance",
    "Shellcode": "shellcode",
    " Shellcode ": "shellcode",
    "Worms": "worms",
}


LABEL_SCHEMA = LabelSchema(
    name="unsw-nb15-attack-category",
    version="1.0",
    mapping=dict(RAW_LABEL_MAP),
    malicious_categories=ATTACK_CATEGORIES,
    benign_category=BENIGN,
    excluded={},
    notes=(
        "Nothing is excluded: every one of the 2,280,090 source records carries a "
        "usable label and all of them are eligible for evaluation.",
        "Whitespace and plural variants of the same family are folded "
        "(' Fuzzers ' -> fuzzers, 'Backdoors' -> backdoor). The full literal "
        "mapping is recorded in `mapping`.",
        "Categories are NOT mapped onto the AEGISX Label enum used by the "
        "synthetic corpus. The taxonomies describe different telemetry classes "
        "and merging them would invent semantics the dataset does not carry.",
        "The binary axis comes from the dataset's own `label` column; a record "
        "whose `label` and `attack_cat` disagree is refused, not repaired.",
    ),
)
