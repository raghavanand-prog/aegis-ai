"""Caps on what analyst feedback may put into the training corpus.

§8 measured that the global cap cannot stop targeted poisoning. It bounds
**volume**; the attack is a **concentration** - 22 rows, 0.34% of the fit set,
comfortably inside a cap set at 20%. No setting short of zero would have stopped
it.

**What honest behaviour looks like**, measured over 8 seeds, admitted-benign
rows per ``event_type``::

    auth_success       114.6      credential_access    1.6
    firewall_allow      84.5      malware_detected     1.4
    process_creation    58.5      data_exfiltration    1.2
    antivirus_scan      46.9      ransomware_behavior  1.1

Under attack, ``malware_detected`` supplies **22**. The discriminating signal is
therefore *not* that a group is large - ``auth_success`` legitimately supplies
114 - but that **a group which is almost never legitimately called benign
suddenly is**. Any flat per-group ceiling loose enough for 114 also admits 22,
which is why this module implements three policies rather than one and expects
the naive policy to fail.

**Grouping is by ``event_type``**, which the normalizer produces before any
detection or labelling. It is *not* the ground-truth attack category, which
production does not have; a defence keyed on that could not ship.

``baseline_relative`` needs a **trusted baseline** of honest per-group rates. That
is a real dependency and a real weakness: an adversary patient enough to poison
the baseline itself would defeat it. It is stated here, tested where it can be,
and left as a limitation rather than papered over.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

POLICY_GLOBAL = "global"
POLICY_PER_GROUP_ABSOLUTE = "per_group_absolute"
POLICY_BASELINE_RELATIVE = "baseline_relative"
POLICIES = (POLICY_GLOBAL, POLICY_PER_GROUP_ABSOLUTE, POLICY_BASELINE_RELATIVE)

#: Multiple of a group's honest baseline that may still be admitted.
#:
#: **Lowered from 3.0 to 1.5 in V6 §11.4.** At 3.0 a patient adversary ratchets
#: its own ceiling: it takes the whole allowance each cycle, every batch stays
#: within policy, and the next cycle's baseline - a mean over history that now
#: includes that batch - rises. Measured over ten cycles, the allowance went
#: 3.5 -> 27.5 and admitted poison reached 22.9 rows, past the ~22 that cost
#: 0.2026 of target recall in §8. At 1.5 the same campaign is contained at 2.3
#: rows.
#:
#: The cost is 0.15% of honest throughput (407.5 rows against 408.1), and it is
#: that small for a structural reason: this bounds *growth*, and honest
#: per-group feedback volume is stationary. Only an attack needs its own
#: contribution to keep rising.
DEFAULT_TOLERANCE = 1.5
#: Rows allowed for a group with no baseline. Small and non-zero: a genuinely
#: new event type should be able to contribute a little, not nothing and not
#: everything.
DEFAULT_FLOOR = 2


@dataclass(frozen=True)
class CapCandidate:
    """One admitted verdict, and the observable group it belongs to."""

    index: int
    group: str


def group_counts(candidates: list[CapCandidate]) -> dict[str, int]:
    return dict(Counter(candidate.group for candidate in candidates))


def apply(
    candidates: list[CapCandidate],
    *,
    policy: str,
    global_ceiling: int,
    per_group_ceiling: int | None = None,
    baseline_rates: dict[str, float] | None = None,
    tolerance: float = DEFAULT_TOLERANCE,
    floor: int = DEFAULT_FLOOR,
) -> list[CapCandidate]:
    """Return the candidates this policy admits, in their original order.

    Order is preserved rather than sampled, so the result is deterministic
    without needing a seed - a cap that admitted a different subset on each run
    would make every downstream measurement irreproducible.
    """
    if policy not in POLICIES:
        raise ValueError(f"unknown cap policy {policy!r}; known: {list(POLICIES)}")

    allowance: dict[str, float] = {}
    if policy == POLICY_PER_GROUP_ABSOLUTE:
        if per_group_ceiling is None:
            raise ValueError("per_group_absolute requires per_group_ceiling")
        allowance = defaultdict(lambda: float(per_group_ceiling))
    elif policy == POLICY_BASELINE_RELATIVE:
        rates = baseline_rates or {}
        allowance = defaultdict(
            lambda: float(floor),
            {group: max(rate * tolerance, floor) for group, rate in rates.items()},
        )

    kept: list[CapCandidate] = []
    used: Counter[str] = Counter()
    for candidate in candidates:
        if len(kept) >= global_ceiling:
            break
        if policy != POLICY_GLOBAL:
            if used[candidate.group] + 1 > allowance[candidate.group]:
                continue
            used[candidate.group] += 1
        kept.append(candidate)
    return kept
