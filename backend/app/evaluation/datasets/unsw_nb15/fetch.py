"""Fetch the UNSW-NB15 corpus.

An explicit operator step, deliberately: the corpus is 230 MB of third-party
licensed data, and nothing in AEGISX should reach out to the network on its own
initiative. Downloaded files are verified against the digests recorded in
:mod:`app.evaluation.datasets.unsw_nb15.loader` before they are usable.

    python -m app.evaluation.datasets.unsw_nb15.fetch
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

from app.evaluation.datasets.unsw_nb15.loader import (
    EXPECTED_DIGESTS,
    SOURCE_URL,
    dataset_dir,
    file_digest,
)

BASE_URL = "https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main/data"
TIMEOUT_SECONDS = 600.0


def download(name: str, destination: Path) -> None:
    url = f"{BASE_URL}/{name}"
    print(f"  fetching {name} from {url}")
    with httpx.stream("GET", url, timeout=TIMEOUT_SECONDS, follow_redirects=True) as response:
        response.raise_for_status()
        with destination.open("wb") as handle:
            for chunk in response.iter_bytes(1024 * 1024):
                handle.write(chunk)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch the UNSW-NB15 evaluation corpus.")
    parser.add_argument(
        "--force", action="store_true", help="re-download files that are already present"
    )
    args = parser.parse_args(argv)

    directory = dataset_dir()
    directory.mkdir(parents=True, exist_ok=True)
    print(f"UNSW-NB15 -> {directory}")
    print(f"Source: {SOURCE_URL}")
    print(
        "Licence: free for academic research with attribution (Moustafa & Slay, 2015). "
        "You are obtaining this from the publisher, not from AEGISX.\n"
    )

    failures = 0
    for name, expected in sorted(EXPECTED_DIGESTS.items()):
        path = directory / name
        if path.exists() and not args.force:
            print(f"  {name} already present")
        else:
            try:
                download(name, path)
            except httpx.HTTPError as exc:
                print(f"  FAILED {name}: {exc}", file=sys.stderr)
                failures += 1
                continue

        actual = file_digest(path)
        if actual == expected:
            print(f"  {name} verified sha256:{actual[:16]}")
        else:
            print(
                f"  DIGEST MISMATCH {name}\n    expected {expected}\n    actual   {actual}",
                file=sys.stderr,
            )
            failures += 1

    if failures:
        print(f"\n{failures} file(s) unusable. The dataset will refuse to load.", file=sys.stderr)
        return 1

    print("\nCorpus ready. Build an experiment with:")
    print("  python -m app.evaluation.run_experiments --help")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
