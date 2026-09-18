#!/usr/bin/env python3
"""Build the standard DEG tables (README format) from a dump plus portal metadata.

Outputs, all joinable on contract_id:
  elections.csv  contract_id,region,election,district
  results.csv    contract_id,candidates,results
  ballots.csv    contract_id,uik,timestamp
  votes.csv      contract_id,timestamp
  uiks.csv       contract_id,uik,initial_voters,added_voters,removed_voters

Metadata comes from the observation portal API (stat.vybory.gov.ru/api), which is
open for reading; responses are cached under --cache so reruns are cheap.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
from portal import API, FEDERAL_COLUMNS, Portal, add_cache_arguments, collect_federal_metadata

MSK = timezone(timedelta(hours=3))
PRINT_LOCK = threading.Lock()


def as_uik(value):
    """The portal/dump send the UIK number as a string; the published tables use ints."""
    return int(value) if isinstance(value, str) and value.isdigit() else value


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, file=sys.stderr, flush=True)


def collect_metadata(portal: Portal, *, federal_details: dict | None = None,
                     include_federal: bool = True) -> tuple[dict, dict, dict]:
    """Return (map_contracts, map_regions, counters)."""
    regions = portal.get("voting/regions")["data"]["regions"]
    map_regions = {region["code"]: (region["name"], region["description"]) for region in regions}
    log(f"regions: {len(regions)}")

    election_paths = [f"elections/region/{region['code']}/elections" for region in regions]
    district_paths: list[str] = []
    for region, payload in zip(regions, portal.get_many(election_paths)):
        for level in payload["data"]["elections"]:
            for election in level["elections"]:
                district_paths.append(
                    f"elections/districts?regionCode={region['code']}&electionId={election['electionId']}"
                )
    log(f"elections: {len(district_paths)} -> districts")

    voting_paths: list[str] = []
    district_results = portal.get_many(district_paths)
    for path, payload in zip(district_paths, district_results):
        election_id = path.split("electionId=")[1]
        for district in payload["data"]:
            voting_paths.append(f"statistics/voting?electionId={election_id}&districtId={district['id']}")
    log(f"districts: {len(voting_paths)} -> votings")

    map_contracts: dict[str, tuple[str, str, str]] = {}
    counters: dict[str, dict] = {}
    for payload in portal.get_many(voting_paths):
        data = payload["data"]
        region_description = map_regions.get(data["regionCode"], ("", data.get("regionName")))[1]
        for voting in data["votings"]:
            contract_id = voting["counters"]["contractId"]
            map_contracts[contract_id] = (
                region_description,
                data["electionName"],
                data["districtName"],
            )
            counters[contract_id] = voting["counters"]
    if include_federal:
        details, federal_counters = collect_federal_metadata(portal)
        for contract, row in details.items():
            map_contracts[contract] = (row["region"], row["election"], row["district"])
        counters.update(federal_counters)
        if federal_details is not None:
            federal_details.update(details)
        log(f"federal contracts with metadata: {len(details)}")
    log(f"contracts with metadata: {len(map_contracts)}")
    return map_contracts, map_regions, counters


def collect_results(portal: Portal, contract_ids: list[str]) -> dict:
    payloads = portal.get_many([f"results/voting/{contract_id}" for contract_id in contract_ids])
    results = {}
    for contract_id, payload in zip(contract_ids, payloads):
        data = payload.get("data") or {}
        answers = data.get("answers") or []
        if answers:
            results[contract_id] = (
                [answer["name"] for answer in answers],
                [answer["value"] for answer in answers],
            )
    log(f"contracts with published results: {len(results)} of {len(contract_ids)}")
    return results


def parse_dump(path: Path) -> tuple[dict, dict, dict, dict, dict]:
    """Single streaming pass over the dump."""
    ballots = defaultdict(list)  # contract -> [(uik, dt)]
    votes = defaultdict(list)  # contract -> [dt]
    voter_lists = defaultdict(list)  # (contract, uik) -> [(optype, count)]
    tallies = {}  # contract -> [votes per candidate] (from the on-chain 'results' operation)
    contract_regions = {}  # contract -> primaryUikRegionCode as seen on chain
    stats = {"blocks": 0, "ops": defaultdict(int), "shard_lengths": [], "bad_lines": 0}
    previous_height = None
    with path.open(encoding="utf-8", errors="replace") as dump:
        for line in dump:
            line = line.strip()
            if not line:
                continue
            try:
                block = json.loads(line)
            except json.JSONDecodeError:
                stats["bad_lines"] += 1
                continue
            height = block.get("height")
            if previous_height is not None and height == 1:
                stats["shard_lengths"].append(previous_height)
            previous_height = height
            stats["blocks"] += 1
            for transaction in block["transactions"]:
                if transaction.get("type") != 105 or transaction["tx"]["type"] != 104:
                    continue
                params = {p["key"]: p["value"] for p in transaction["tx"]["params"]}
                operation = params.get("operation")
                stats["ops"][operation] += 1
                timestamp = transaction["tx"]["timestamp"]
                when = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).astimezone(MSK).replace(
                    tzinfo=None, microsecond=0
                )
                contract_id = transaction["tx"]["contractId"]
                if "primaryUikRegionCode" in params and contract_id not in contract_regions:
                    contract_regions[contract_id] = str(params["primaryUikRegionCode"])
                if operation == "blindSigIssue":
                    ballots[contract_id].append((as_uik(params["primaryUikNumber"]), when))
                elif operation == "vote":
                    votes[contract_id].append(when)
                elif operation in ("addVotersList", "removeFromVotersList", "addToVotersList"):
                    count = len(json.loads(params["userIdHashes"]))
                    voter_lists[(contract_id, as_uik(params["primaryUikNumber"]))].append((operation, count))
                elif operation == "results" and params.get("results"):
                    # Multi-dimension bulletins are nested: [[candidate tallies], ...] -> first dimension.
                    tallies[contract_id] = json.loads(params["results"])[0]
    stats["shard_lengths"].append(previous_height)
    return ballots, votes, voter_lists, tallies, contract_regions, stats


def write_tables(
    out_dir: Path,
    map_contracts: dict,
    map_regions: dict,
    results: dict,
    ballots: dict,
    votes: dict,
    voter_lists: dict,
    tallies: dict,
    counters: dict,
    contract_regions: dict,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Rows follow the chain (that is what the dump contains); the portal adds names only where it
    # knows the contract. Chain-only contracts get their region from primaryUikRegionCode, while
    # election/district stay empty.
    chain_contracts = sorted(set(ballots) | set(votes) | set(tallies) | {c for c, _ in voter_lists})
    rows = []
    for contract_id in chain_contracts:
        region, election, district = map_contracts.get(contract_id, ("", "", ""))
        if not region:
            code = contract_regions.get(contract_id)
            if code is not None and code.isdigit() and int(code) in map_regions:
                region = map_regions[int(code)][1]
        rows.append((contract_id, region, election, district))
    elections_df = pd.DataFrame(rows, columns=["contract_id", "region", "election", "district"])
    elections_df.to_csv(out_dir / "elections.csv", index=False)

    # Candidate names come from the portal, tallies from the chain (the 2024/2025 pipeline did the
    # same and asserted both agree); if the portal has nothing published, the names stay empty.
    results_df = pd.DataFrame(
        [
            (
                contract_id,
                results.get(contract_id, ([], None))[0],
                results[contract_id][1] if contract_id in results else tallies.get(contract_id, []),
            )
            for contract_id in chain_contracts
        ],
        columns=["contract_id", "candidates", "results"],
    )
    results_df.to_csv(out_dir / "results.csv", index=False)

    # Diagnostic: dump counts vs the portal's live counters, per chain contract.
    diagnostics = [
        (
            contract_id,
            len(ballots.get(contract_id, [])),
            len(votes.get(contract_id, [])),
            counters.get(contract_id, {}).get("issued"),
            counters.get(contract_id, {}).get("voted"),
            len(tallies.get(contract_id, [])),
            bool(map_contracts.get(contract_id)),
        )
        for contract_id in chain_contracts
    ]
    pd.DataFrame(
        diagnostics,
        columns=[
            "contract_id",
            "dump_ballots",
            "dump_votes",
            "api_issued",
            "api_voted",
            "tally_len",
            "in_portal_metadata",
        ],
    ).to_csv(out_dir / "per_contract.csv", index=False)

    ballots_df = pd.DataFrame(
        [
            (contract_id, uik, when)
            for contract_id, rows in sorted(ballots.items())
            for uik, when in sorted(rows, key=lambda row: row[1])
        ],
        columns=["contract_id", "uik", "timestamp"],
    )
    ballots_df.to_csv(out_dir / "ballots.csv", index=False)

    votes_df = pd.DataFrame(
        [
            (contract_id, when)
            for contract_id, rows in sorted(votes.items())
            for when in sorted(rows)
        ],
        columns=["contract_id", "timestamp"],
    )
    votes_df.to_csv(out_dir / "votes.csv", index=False)

    uiks_df = pd.DataFrame(
        [
            (
                contract_id,
                uik,
                sum(count for operation, count in rows if operation == "addVotersList"),
                sum(count for operation, count in rows if operation == "addToVotersList"),
                sum(count for operation, count in rows if operation == "removeFromVotersList"),
            )
            for (contract_id, uik), rows in sorted(voter_lists.items())
        ],
        columns=["contract_id", "uik", "initial_voters", "added_voters", "removed_voters"],
    )
    uiks_df.to_csv(out_dir / "uiks.csv", index=False)

    return {
        "elections.csv": len(elections_df),
        "results.csv": len(results_df),
        "ballots.csv": len(ballots_df),
        "votes.csv": len(votes_df),
        "uiks.csv": len(uiks_df),
        "per_contract.csv": len(diagnostics),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=None, help="API response cache (default: OUT/cache)")
    parser.add_argument("--workers", type=int, default=8)
    add_cache_arguments(parser)
    parser.add_argument("--skip-federal", action="store_true",
                        help="skip federal API v2 (e.g. for older/training portals)")
    parser.add_argument(
        "--api",
        default=API,
        help="portal base URL (use https://teststat.deg.rt.ru/api from the test network)",
    )
    parser.add_argument("--skip-api", action="store_true", help="build only dump-derived tables")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be positive")

    out_dir = args.out.resolve()
    cache_dir = args.cache or out_dir / "cache"

    federal_details = {}
    if args.skip_api:
        map_contracts, map_regions, results, counters = {}, {}, {}, {}
    else:
        with Portal(cache_dir, args.workers, args.api, args.cache_ttl, args.refresh_cache) as portal:
            map_contracts, map_regions, counters = collect_metadata(
                portal, federal_details=federal_details, include_federal=not args.skip_federal,
            )
            # No results exist yet for active federal votings. Avoid querying
            # their result endpoint before the metadata says they are published.
            result_contracts = [contract for contract in map_contracts
                                if contract not in federal_details
                                or federal_details[contract]["has_results"] is not False]
            results = collect_results(portal, sorted(result_contracts))
            log(f"API calls: {portal.calls}, cache hits: {portal.cache_hits}")

    log(f"parsing dump {args.dump}")
    ballots, votes, voter_lists, tallies, contract_regions, stats = parse_dump(args.dump)
    log(f"on-chain tallies: {len(tallies)}")
    log(f"blocks: {stats['blocks']}, shard lengths: {stats['shard_lengths']}, ops: {dict(stats['ops'])}")
    if stats["bad_lines"]:
        log(f"WARNING: skipped {stats['bad_lines']} unparsable lines")

    counts = write_tables(
        out_dir,
        map_contracts,
        map_regions,
        results,
        ballots,
        votes,
        voter_lists,
        tallies,
        counters,
        contract_regions,
    )
    log(f"wrote {counts} into {out_dir}")
    # Keep the established elections.csv schema; expose the additional identity
    # fields separately so SINGLE and UNION contracts are never joined by name.
    pd.DataFrame(
        [federal_details[key] for key in sorted(federal_details)], columns=FEDERAL_COLUMNS,
    ).to_csv(out_dir / "federal_contracts.csv", index=False)

    if counters:
        issued = sum(c["issued"] for c in counters.values())
        voted = sum(c["voted"] for c in counters.values())
        all_voters = sum(c["all"] for c in counters.values())
        dump_ballots = sum(len(rows) for rows in ballots.values())
        dump_votes = sum(len(rows) for rows in votes.values())
        print(f"portal counters: all={all_voters} issued={issued} voted={voted}")
        print(f"dump:            ballots={dump_ballots} votes={dump_votes}")
        print(
            "coverage: "
            f"ballots={dump_ballots / issued:.1%} votes={dump_votes / voted:.1%}"
            if issued and voted
            else "coverage: n/a"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
