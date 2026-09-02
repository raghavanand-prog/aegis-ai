"""Wall-clock ceiling for long-running evaluation and training commands.

Why this exists, concretely: a self-deadlock in the database session factory
(`get_session_factory` held a non-reentrant lock and then called `get_engine`,
which took it again) left `python -m app.ml.evaluation.run_ml_eval` blocked at
zero CPU, having written nothing. It was noticed only because someone looked -
a watcher waiting on output from a process that will never produce any is
indistinguishable from a watcher waiting on a slow one.

The lock bug is fixed. This is the second line of defence: an evaluation that
stops making progress should die with a diagnosis, not hang. It matters most in
CI, where a hung step burns the whole job timeout and reports nothing useful.

Implemented with a daemon timer thread rather than `signal.alarm` so it works
on any platform and from any thread, and rather than shelling out to
`timeout(1)`, which macOS does not ship.
"""

from __future__ import annotations

import faulthandler
import os
import sys
import threading

#: Generous relative to a healthy run (the hybrid evaluation takes ~20s, a
#: threshold sweep ~4 minutes) and far below any sensible CI job timeout.
DEFAULT_MAX_SECONDS = 900

#: Exit code used when the ceiling is hit. Matches the 128+SIGALRM convention
#: `timeout(1)` uses, so a CI log reads the same way on either platform.
TIMEOUT_EXIT_CODE = 142


def start(max_seconds: int | None = None, *, label: str = "evaluation") -> threading.Timer | None:
    """Arm a wall-clock ceiling for the current process.

    Returns the timer so a caller can ``cancel()`` it on success. ``None`` (and
    no ceiling) when ``max_seconds`` is 0 or negative, which is the documented
    way to opt out.

    On expiry it dumps every thread's stack before exiting. That is the whole
    value of failing this way rather than being killed from outside: the stack
    names the deadlock instead of leaving you to guess at it.
    """
    seconds = DEFAULT_MAX_SECONDS if max_seconds is None else max_seconds
    if seconds <= 0:
        return None

    def _expire() -> None:
        print(
            f"\nerror: {label} exceeded its {seconds}s ceiling and was stopped.\n"
            "Thread stacks follow - if they show no progress, this is a hang, "
            "not slowness.",
            file=sys.stderr,
            flush=True,
        )
        faulthandler.dump_traceback(file=sys.stderr)
        sys.stderr.flush()
        # os._exit, not sys.exit: a deadlocked interpreter will not unwind, and
        # a SystemExit raised on the timer thread would not reach the one that
        # is stuck.
        os._exit(TIMEOUT_EXIT_CODE)

    timer = threading.Timer(seconds, _expire)
    timer.daemon = True
    timer.start()
    return timer


def add_argument(parser) -> None:  # noqa: ANN001 - argparse.ArgumentParser
    """Add the standard ``--max-seconds`` flag to an evaluation CLI."""
    parser.add_argument(
        "--max-seconds",
        type=int,
        default=DEFAULT_MAX_SECONDS,
        help=(
            "Wall-clock ceiling in seconds; the run exits "
            f"{TIMEOUT_EXIT_CODE} with thread stacks if it is exceeded. "
            "0 disables the ceiling."
        ),
    )
