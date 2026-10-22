#!/usr/bin/env python3
"""Find a transaction ID in JSONL chunks written by ``monitor.py``.

Example::

    python search-transaction.py CRCFzVSjz5GWFCdE9vx7Ah7qoYNkG6BDTyE8wytLGvUf \
        --input-dir block-monitor

All matching occurrences are printed.  The exit status is 0 when at least one
transaction was found and 1 when the ID is absent.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


MSK = timezone(timedelta(hours=3), name="MSK")
ID_KEYS = frozenset({"id", "txId", "transactionId", "transaction_id"})


@dataclass(frozen=True)
class Match:
    path: Path
    line_number: int
    block: dict[str, Any]
    transaction_index: int
    transaction: Any
    matched_fields: tuple[str, ...]


def exact_id_fields(value: Any, target: str, path: str = "") -> Iterator[str]:
    """Yield paths whose ID-like field equals target."""
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            if key in ID_KEYS and child == target:
                yield child_path
            yield from exact_id_fields(child, target, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from exact_id_fields(child, target, f"{path}[{index}]")


def transaction_kind(transaction: Any) -> str:
    if not isinstance(transaction, dict):
        return "invalid"
    if transaction.get("type") == 105:
        inner = transaction.get("tx")
        if isinstance(inner, dict):
            if inner.get("type") == 103:
                return "createContract"
            if inner.get("type") == 104:
                for parameter in inner.get("params") or []:
                    if isinstance(parameter, dict) and parameter.get("key") == "operation":
                        for key in (
                            "value",
                            "stringValue",
                            "intValue",
                            "boolValue",
                            "booleanValue",
                        ):
                            if key in parameter and parameter[key] not in (None, ""):
                                return str(parameter[key])
                return "contractCall"
            return f"inner-type-{inner.get('type')}"
    return f"type-{transaction.get('type', 'unknown')}"


def block_timestamp(value: Any) -> str:
    try:
        numeric = float(value)
        milliseconds = abs(numeric) >= 100_000_000_000
        moment = datetime.fromtimestamp(
            numeric / 1000 if milliseconds else numeric,
            tz=timezone.utc,
        ).astimezone(MSK)
    except (TypeError, ValueError, OverflowError, OSError):
        return "unknown"
    return moment.isoformat(timespec="milliseconds" if milliseconds else "seconds")


def input_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.is_dir():
        raise FileNotFoundError(root)
    return sorted(path for path in root.rglob("*.jsonl") if path.is_file())


def search_file(path: Path, target: str) -> Iterator[Match]:
    try:
        stream = path.open(encoding="utf-8", errors="replace")
    except OSError as error:
        print(f"warning: cannot open {path}: {error}", file=sys.stderr)
        return

    with stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                block = json.loads(line)
            except json.JSONDecodeError as error:
                # Atomic chunks should never contain a partial line.  Ignore a
                # manually copied/in-progress file and keep scanning others.
                print(f"warning: invalid JSON in {path}:{line_number}: {error}", file=sys.stderr)
                continue
            if not isinstance(block, dict):
                continue
            transactions = block.get("transactions")
            if not isinstance(transactions, list):
                continue
            for transaction_index, transaction in enumerate(transactions):
                fields = tuple(exact_id_fields(transaction, target))
                if fields:
                    yield Match(
                        path=path,
                        line_number=line_number,
                        block=block,
                        transaction_index=transaction_index,
                        transaction=transaction,
                        matched_fields=fields,
                    )


def relative_location(path: Path, root: Path) -> str:
    if root.is_dir():
        try:
            return str(path.relative_to(root))
        except ValueError:
            pass
    return str(path)


def print_match(match: Match, target: str, root: Path, first: bool) -> None:
    if not first:
        print("\n--- another match ---")
    block = match.block
    print(f"found: {target}")
    print(f"file: {relative_location(match.path, root)}:{match.line_number}")
    print(f"block: {block.get('height', 'unknown')}")
    print(f"shard: {match.path.parent.name}")
    print(f"block_timestamp: {block_timestamp(block.get('timestamp'))}")
    print(f"transaction_index: {match.transaction_index}")
    print(f"kind: {transaction_kind(match.transaction)}")
    print(f"matched_fields: {', '.join(match.matched_fields)}")
    print("transaction:")
    print(json.dumps(match.transaction, ensure_ascii=False, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transaction_id", help="transaction ID, for example a base58 hash")
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("block-monitor"),
        help="monitor output directory or one JSONL file (default: block-monitor)",
    )
    args = parser.parse_args()

    try:
        paths = input_files(args.input_dir)
    except FileNotFoundError:
        print(f"not found: input path does not exist: {args.input_dir}", file=sys.stderr)
        return 2

    matches = 0
    for path in paths:
        for match in search_file(path, args.transaction_id):
            print_match(match, args.transaction_id, args.input_dir, first=(matches == 0))
            matches += 1

    if matches == 0:
        print(f"not found: {args.transaction_id}", file=sys.stderr)
        return 1
    print(f"matches: {matches}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(0)
