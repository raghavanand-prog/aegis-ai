"""The seed plan shared by every AEGISX adaptation experiment.

V5 reported three seeds and said so plainly: with a both-arms F1 spread of
0.117-0.333 the effect size was suggestive, not settled. V6 Track 1 answers that
with substantially more seeds, which puts two requirements on this module.

**A longer plan must extend a shorter one.** ``build_seeds(50)`` begins with
``build_seeds(3)``. Resampling would make each V6 run incomparable with the one
before it, and would quietly invalidate ``docs/V5_RESEARCH_REPORT.md``, whose
published command is ``--seeds 3``.

**The plan is fixed, not drawn per run.** A seed list that varies between
invocations is a result nobody else can regenerate.

The first five seeds are the ones the V5 runner hard-coded; everything past them
is drawn from one fixed stream.
"""

from __future__ import annotations

import random

#: The seeds V5 used, in the order it used them. The first three produced the
#: published V5 numbers and are load-bearing for that report's reproducibility.
V5_SEEDS = (1337, 4242, 99, 2024, 7)

#: Fixed stream for seeds beyond V5's five. Not a secret, and deliberately not
#: drawn from the system entropy pool - a plan that changes per run is not a
#: plan.
_EXTENSION_STREAM = 20260903
_SEED_RANGE = 1_000_000


def build_seeds(count: int) -> list[int]:
    """Return the first ``count`` seeds of the standing plan."""
    if count < 1:
        raise ValueError("a seed plan needs at least one seed")

    plan = list(V5_SEEDS[:count])
    if len(plan) == count:
        return plan

    # noqa justification: reproducibility, not secrecy. The same argument the
    # feedback simulator carries - a result that cannot be regenerated from its
    # seed plan is not a result.
    rng = random.Random(_EXTENSION_STREAM)  # noqa: S311
    used = set(plan)
    while len(plan) < count:
        candidate = rng.randrange(_SEED_RANGE)
        if candidate in used:
            continue
        used.add(candidate)
        plan.append(candidate)
    return plan
