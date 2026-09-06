"""Who is acting, and whether they are a person.

One definition, used by every place that separates duties. There were two
before this module, and **they disagreed**:

* ``adaptation/proposals/service.py`` (V7) compared the raw actor string
  against the non-human prefixes, so ``AI:analyst`` and ``  ai:analyst  ``
  passed a check meant to stop exactly that;
* ``incidents/lifecycle.py`` (V9 Phase B) folded case and whitespace first, so
  the same strings were refused.

The V7 gap is narrow in practice - the API supplies ``user.email``, and an
email is unlikely to start ``AI:`` - but V7's own docstring is explicit that
the service layer is the boundary *because the API is one caller among
several*. A rule that holds only for the caller that happens to be well
behaved is not the rule that was documented.

Phase E needed the same check a third time. Three copies of a
separation-of-duties rule is how one of them quietly stops matching the others,
so there is now one, and a test asserts every consumer agrees.

The rule itself is deliberately small: an actor is a machine when its
identifier is namespaced ``ai:``, ``system:`` or ``automation:``. Machines may
observe, detect, draft and recommend. They may not approve, contain or close -
those need a person, and this is where "a person" is defined.
"""

from __future__ import annotations

#: Actor prefixes that name a process rather than a person. Namespaced with a
#: colon so they cannot collide with an email address.
NON_HUMAN_ACTOR_PREFIXES: tuple[str, ...] = ("ai:", "system:", "automation:")


def normalize_actor(actor: str | None) -> str:
    """Fold an actor identifier for comparison.

    Case and surrounding whitespace, because actors are email addresses and
    ``Admin@Aegisx.dev`` is the same account as ``admin@aegisx.dev``. Any
    comparison that skipped this could be defeated with a shift key.
    """
    return (actor or "").strip().casefold()


def is_human_actor(actor: str | None) -> bool:
    """Whether this identifier names a person.

    Fails closed on an absent or empty actor: an unnamed caller must not
    inherit a person's authority just because nothing was recorded about it.
    """
    normalized = normalize_actor(actor)
    if not normalized:
        return False
    return not normalized.startswith(NON_HUMAN_ACTOR_PREFIXES)


def same_actor(left: str | None, right: str | None) -> bool:
    """Whether two identifiers name the same person.

    Two absent actors are **not** the same actor. Returning True there would
    let a four-eyes check pass on a pair of blanks.
    """
    normalized_left = normalize_actor(left)
    if not normalized_left:
        return False
    return normalized_left == normalize_actor(right)
