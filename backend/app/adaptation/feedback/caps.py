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

**V7: a second axis.** V6 §19.2 measured the per-group cap removing 96% of
poison where a scenario owned its ``event_type`` and only **40%** where it hid
in a high-volume group; §20.3 found a hidden target facing an allowance of ~597
at cycle zero, needing no patience at all. That is not a tuning problem. *Any*
single-axis cap is only as good as its key, and ``event_type`` is partly
attacker-influenced, so the evasion is simply to move.

``actor_policy`` adds an independent per-submitter ceiling. The reason it
complements rather than duplicates the group cap: a campaign spread across ten
event types divides its per-group footprint by ten and leaves its per-actor
footprint **unchanged**. Both axes must admit, so evading one now requires
evading the other, and the two are evaded by opposite behaviours - concentrating
to stay under the actor cap means concentrating into a group, and spreading to
stay under the group cap means spreading from one account.

What this does **not** claim: it bounds a *compromised actor*, not a colluding
set of them. An adversary holding several analyst accounts divides their
per-actor footprint the same way moving between groups divided the per-group
one. That is the honest residual, and it is a harder attack to mount than the
one V6 measured.
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


#: Bucket for feedback with no attributable actor. Simulated and imported rows
#: have no analyst, and leaving them unbounded would make "turn on the actor cap"
#: a way to *remove* a limit. They share one allowance instead - fail closed.
UNATTRIBUTED_ACTOR = "<unattributed>"


@dataclass(frozen=True)
class CapCandidate:
    """One admitted verdict and the observable axes it can be capped along.

    ``group`` is the V6 axis - the normalizer's ``event_type``. ``actor`` is the
    V7 addition: who submitted the verdict. Both are observable in production
    before any labelling, which is the property that makes either usable as a
    defence at all.
    """

    index: int
    group: str
    #: ``None`` where the row has no attributable submitter. Bucketed into
    #: ``UNATTRIBUTED_ACTOR`` rather than exempted; see that constant.
    actor: str | None = None

    @property
    def actor_key(self) -> str:
        return self.actor or UNATTRIBUTED_ACTOR


@dataclass(frozen=True)
class DimensionPolicy:
    """A ceiling along one axis of a batch.

    Extracted in V7 so the group axis and the actor axis are the same mechanism
    rather than two implementations that could drift. ``policy`` is
    ``per_group_absolute`` (a flat ceiling) or ``baseline_relative`` (a multiple
    of that key's honest history).
    """

    policy: str
    ceiling: int | None = None
    baseline_rates: dict[str, float] | None = None
    tolerance: float = DEFAULT_TOLERANCE
    floor: int = DEFAULT_FLOOR

    def allowances(self) -> defaultdict[str, float]:
        if self.policy == POLICY_PER_GROUP_ABSOLUTE:
            if self.ceiling is None:
                raise ValueError("per_group_absolute requires a ceiling")
            ceiling = float(self.ceiling)
            return defaultdict(lambda: ceiling)
        if self.policy == POLICY_BASELINE_RELATIVE:
            rates = self.baseline_rates or {}
            floor = float(self.floor)
            return defaultdict(
                lambda: floor,
                {key: max(rate * self.tolerance, floor) for key, rate in rates.items()},
            )
        raise ValueError(
            f"unknown dimension policy {self.policy!r}; known: "
            f"{[POLICY_PER_GROUP_ABSOLUTE, POLICY_BASELINE_RELATIVE]}"
        )


def group_counts(candidates: list[CapCandidate]) -> dict[str, int]:
    return dict(Counter(candidate.group for candidate in candidates))


def actor_counts(candidates: list[CapCandidate]) -> dict[str, int]:
    return dict(Counter(candidate.actor_key for candidate in candidates))


def apply(
    candidates: list[CapCandidate],
    *,
    policy: str,
    global_ceiling: int,
    per_group_ceiling: int | None = None,
    baseline_rates: dict[str, float] | None = None,
    tolerance: float = DEFAULT_TOLERANCE,
    floor: int = DEFAULT_FLOOR,
    actor_policy: DimensionPolicy | None = None,
) -> list[CapCandidate]:
    """Return the candidates every configured axis admits, in original order.

    Order is preserved rather than sampled, so the result is deterministic
    without needing a seed - a cap that admitted a different subset on each run
    would make every downstream measurement irreproducible.

    **``actor_policy`` is the V7 addition and defaults to off**, so a call that
    does not pass it behaves exactly as it did in V6 and every published
    experiment reproduces unchanged.

    Why a second axis at all: V6 §19.2 measured the per-group cap removing 96%
    of poison where a scenario owned its ``event_type`` and **40%** where it hid
    in a high-volume group, and §20.3 found a hidden target facing an allowance
    of ~597 at cycle zero. The weakness is structural rather than a matter of
    tuning - *any* single-axis cap is only as good as its key, and ``event_type``
    is partly attacker-influenced, so an adversary evades it by moving. A
    compromised **actor**, by contrast, carries their identity across every group
    they touch: spreading a campaign over ten event types divides the per-group
    footprint by ten and leaves the per-actor footprint exactly where it was.

    The two axes are independent and both must admit. A candidate refused by
    either consumes allowance on **neither**, so a batch blocked on one axis
    cannot exhaust the other's budget as a side effect.
    """
    if policy not in POLICIES:
        raise ValueError(f"unknown cap policy {policy!r}; known: {list(POLICIES)}")

    group_allowance: defaultdict[str, float] | None = None
    if policy != POLICY_GLOBAL:
        group_allowance = DimensionPolicy(
            policy=policy,
            ceiling=per_group_ceiling,
            baseline_rates=baseline_rates,
            tolerance=tolerance,
            floor=floor,
        ).allowances()

    actor_allowance = actor_policy.allowances() if actor_policy is not None else None

    kept: list[CapCandidate] = []
    group_used: Counter[str] = Counter()
    actor_used: Counter[str] = Counter()

    for candidate in candidates:
        if len(kept) >= global_ceiling:
            break

        # Both axes are tested before either is charged. Charging as we go would
        # let a candidate rejected by the actor cap still consume its group's
        # budget, which would turn enabling one defence into a way of weakening
        # the other.
        if (
            group_allowance is not None
            and group_used[candidate.group] + 1 > group_allowance[candidate.group]
        ):
            continue
        if (
            actor_allowance is not None
            and actor_used[candidate.actor_key] + 1 > actor_allowance[candidate.actor_key]
        ):
            continue

        if group_allowance is not None:
            group_used[candidate.group] += 1
        if actor_allowance is not None:
            actor_used[candidate.actor_key] += 1
        kept.append(candidate)

    return kept
