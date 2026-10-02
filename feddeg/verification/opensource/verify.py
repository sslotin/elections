#!/usr/bin/env python3
"""Verify an original DEG blockchain dump without creating intermediate files.

Usage::

    python3 verify.py /data/edg2025.zip
    python3 verify.py /data/edg2025.zip --results-only
    python3 verify.py /data/edg2025.zip --workers 4

Transactions are read as a stream.  The verifier retains only contract state,
voter-key uniqueness sets and one Jacobian ciphertext accumulator per active
election; it does not materialize the raw dump or write CSV/report files.
"""

from __future__ import annotations

import sys

# The verifier is intentionally read-only: do not create Python bytecode files
# next to the source while importing the crypto package.
sys.dont_write_bytecode = True

import argparse
import json
from pathlib import Path

from crypto.stream import verify


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("dump", type=Path,
                        help="original JSONL, ZIP/gzip dump, or JSONL chunk directory")
    parser.add_argument(
        "--results-only", action="store_true",
        help="skip transaction/ballot signatures and proofs; aggregate ciphertexts and verify the final decryption",
    )
    parser.add_argument(
        "--exclude-ballots", type=Path,
        help="JSON object mapping previously failed ballot tx IDs to reasons; requires --results-only",
    )
    parser.add_argument(
        "--workers", "--threads", dest="workers", type=positive_int, default=1,
        help="parallel ballot-verification processes (default: 1)",
    )
    args = parser.parse_args(argv)
    if not args.dump.exists():
        parser.error(f"dump does not exist: {args.dump}")
    if args.exclude_ballots and not args.results_only:
        parser.error("--exclude-ballots requires --results-only")
    exclusions = None
    if args.exclude_ballots:
        try:
            exclusions = json.loads(args.exclude_ballots.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            parser.error(f"cannot read --exclude-ballots JSON: {error}")
        if (not isinstance(exclusions, dict) or
                any(not isinstance(tx_id, str) or not isinstance(reason, str) or not reason
                    for tx_id, reason in exclusions.items())):
            parser.error("--exclude-ballots must map transaction IDs to nonempty reason strings")
    return verify(args.dump, workers=args.workers, results_only=args.results_only,
                  excluded_ballots=exclusions)


if __name__ == "__main__":
    raise SystemExit(main())
