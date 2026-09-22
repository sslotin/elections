#!/usr/bin/env python3
"""Look up the official candidate order for DEG contract IDs.

The blockchain stores option positions and encrypted votes, not candidate labels.
This script queries the public stat.vybory.gov.ru result protocol by contract ID:

    python3 lookup_names.py FcP24ZJFuRJW9HeiHwQD9uHHJWUkfgvnaDhR7MH53r9g
    python3 lookup_names.py --report deg-verify.json

The exact strings from ``answers[].name`` are preserved.  ``answers`` order is
also preserved; do not sort it, because the position is the ballot option index.
No credentials are needed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

DEFAULT_BASE_URL = "https://stat.vybory.gov.ru"
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "Chrome/140.0 Safari/537.36"
)


class LookupError(RuntimeError):
    """A remote lookup or response-format failure."""


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LookupError(f"cannot read JSON {path}: {exc}") from exc


def report_contract_ids(path: Path) -> list[str]:
    """Extract contract IDs from a deg-verify report's ``votes[].sent`` fields."""
    report = read_json(path)
    votes = report.get("votes") if isinstance(report, dict) else None
    if not isinstance(votes, list):
        raise LookupError(f"{path}: expected a report with a votes array")

    result: list[str] = []
    for vote in votes:
        if not isinstance(vote, dict):
            continue
        sent = vote.get("sent")
        if isinstance(sent, dict):
            transaction = sent
        elif isinstance(sent, str):
            try:
                transaction = json.loads(sent)
            except json.JSONDecodeError:
                continue
        else:
            continue
        if isinstance(transaction, dict) and isinstance(transaction.get("contractId"), str):
            result.append(transaction["contractId"])
    return result


def file_contract_ids(path: Path) -> list[str]:
    """Read whitespace-separated IDs, one or more per line."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise LookupError(f"cannot read IDs file {path}: {exc}") from exc
    return [token for line in text.splitlines() for token in line.split("#", 1)[0].split()]


def unique_ids(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def get_json(base_url: str, path: str, timeout: float, retries: int) -> tuple[str, Any]:
    """GET one public API resource, retrying transient failures."""
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urlopen(request, timeout=timeout) as response:  # nosec B310: fixed HTTPS base
                payload = json.loads(response.read().decode("utf-8"))
            return url, payload
        except HTTPError as exc:
            last_error = exc
            # 4xx errors are normally permanent; retry only rate limits/server errors.
            transient = exc.code == 429 or 500 <= exc.code <= 599
            if not transient or attempt >= retries:
                detail = exc.read().decode("utf-8", "replace")[:300]
                raise LookupError(f"HTTP {exc.code} for {url}: {detail}") from exc
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt >= retries:
                raise LookupError(f"failed to fetch {url}: {exc}") from exc
        if attempt < retries:
            time.sleep(min(2.0 ** attempt, 8.0))
    raise LookupError(f"failed to fetch {url}: {last_error}")


def normalize_result(contract_id: str, source_url: str, payload: Any) -> dict[str, Any]:
    """Keep protocol metadata and the complete answer order, without reordering."""
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise LookupError(f"{contract_id}: API returned no published protocol data")
    answers = data.get("answers")
    if not isinstance(answers, list):
        raise LookupError(f"{contract_id}: protocol has no answers array")

    normalized_answers = []
    for position, answer in enumerate(answers, 1):
        if not isinstance(answer, dict) or not isinstance(answer.get("name"), str):
            raise LookupError(f"{contract_id}: malformed answers[{position - 1}]")
        normalized_answers.append(
            {
                "position": position,
                "num": answer.get("num"),
                "name": answer["name"],
                "value": answer.get("value"),
                "valuePercent": answer.get("valuePercent"),
                "disabled": answer.get("disabled"),
            }
        )

    return {
        "contractId": contract_id,
        "source": source_url,
        "regionCode": data.get("regionCode"),
        "regionName": data.get("regionName"),
        "electionName": data.get("electionName"),
        "type": data.get("type"),
        "districtName": data.get("districtName"),
        "signInvalidResult": data.get("signInvalidResult"),
        "answers": normalized_answers,
    }


def print_text(item: dict[str, Any], with_values: bool) -> None:
    print(f"\n{item['contractId']}")
    print(
        f"  {item.get('regionName') or ''} | {item.get('electionName') or ''} | "
        f"{item.get('type') or ''} | {item.get('districtName') or ''}"
    )
    print(f"  signInvalidResult={item.get('signInvalidResult')!r}")
    for answer in item["answers"]:
        suffix = ""
        if with_values:
            suffix = f"\tvalue={answer['value']}\tpercent={answer['valuePercent']}"
        print(f"  {answer['position']}\t{answer['name']}{suffix}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Look up official candidate names/order by DEG contract ID."
    )
    parser.add_argument("contract_ids", nargs="*", help="one or more contract IDs")
    parser.add_argument(
        "--report",
        action="append",
        type=Path,
        default=[],
        help="extract contract IDs from a deg-verify JSON report; repeatable",
    )
    parser.add_argument(
        "--ids-file",
        action="append",
        type=Path,
        default=[],
        help="read whitespace-separated contract IDs; repeatable",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds")
    parser.add_argument("--retries", type=int, default=3, help="retries for transient failures")
    parser.add_argument(
        "--with-values",
        action="store_true",
        help="also print official vote totals and percentages",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="write normalized results as JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.retries < 0:
        parser.error("--timeout must be positive and --retries cannot be negative")

    ids = list(args.contract_ids)
    for path in args.report:
        ids.extend(report_contract_ids(path))
    for path in args.ids_file:
        ids.extend(file_contract_ids(path))
    if not ids and not sys.stdin.isatty():
        ids.extend(sys.stdin.read().split())
    ids = unique_ids(ids)
    if not ids:
        parser.error("provide contract IDs, --report, --ids-file, or IDs on stdin")

    results: list[dict[str, Any]] = []
    failures = 0
    for contract_id in ids:
        try:
            encoded_id = quote(contract_id, safe="")
            source_url, payload = get_json(
                args.base_url,
                f"/api/results/voting/{encoded_id}",
                args.timeout,
                args.retries,
            )
            item = normalize_result(contract_id, source_url, payload)
            results.append(item)
            if not args.as_json:
                print_text(item, args.with_values)
        except LookupError as exc:
            failures += 1
            print(f"ERROR {contract_id}: {exc}", file=sys.stderr)

    if args.as_json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
