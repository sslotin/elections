#!/usr/bin/env python3
"""Compare existing CSV tables to portal aggregates without fetching transactions."""

from __future__ import annotations

import argparse
import csv
import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from portal import API, Portal, add_cache_arguments

MSK = timezone(timedelta(hours=3))
HOUR = timedelta(hours=1)
HOURLY_COLUMNS = [
    "contract_id", "hour_start_msk", "hour_end_msk", "dump_votes", "api_votes",
    "votes_delta", "dump_ballots", "api_ballots", "ballots_delta", "status",
    "time_offset", "checked_at_msk", "declared_from_msk", "declared_through_msk",
]
UIK_COLUMNS = ["contract_id", "uik", "all", "issued", "turnout_percent", "collection_time"]


def moscow_time(value: str) -> datetime:
    """CSV/CLI naive timestamps mean Moscow time, regardless of host timezone."""
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=MSK) if parsed.tzinfo is None else parsed.astimezone(MSK)


def full_hours(start: datetime, through: datetime):
    hour = start.replace(minute=0, second=0, microsecond=0)
    if hour < start:
        hour += HOUR
    while hour + HOUR <= through:
        yield hour
        hour += HOUR


def read_tables(directory: Path, start=None, through=None, selected=None):
    """Stream the CSVs, retaining only counts in the explicitly declared window."""
    with (directory / "elections.csv").open(encoding="utf-8", newline="") as stream:
        contracts = {row["contract_id"] for row in csv.DictReader(stream)}
    votes, ballots = Counter(), Counter()
    if start is not None:
        for filename, counts in (("votes.csv", votes), ("ballots.csv", ballots)):
            with (directory / filename).open(encoding="utf-8", newline="") as stream:
                for row in csv.DictReader(stream):
                    contract = row["contract_id"]
                    contracts.add(contract)
                    if selected is not None and contract not in selected:
                        continue
                    when = moscow_time(row["timestamp"])
                    if start <= when < through:
                        counts[(contract, when.replace(minute=0, second=0, microsecond=0))] += 1
    if selected is not None:
        unknown = selected - contracts
        if unknown:
            raise ValueError(f"contracts not found in input tables: {sorted(unknown)}")
        contracts = selected
    return sorted(contracts), votes, ballots


def hourly_rows(contract, series, votes, ballots, start, through, *, now=None, lag_minutes=5):
    """Portal points label the END of [hour_start, hour_end), in local time.

    timeOffset is local-minus-Moscow, not local-minus-UTC. Only points with
    published cumulative counters are comparable; future placeholder zeros
    have no such counters. Matching counts is not proof of a complete chain.
    """
    now = now or datetime.now(MSK)
    offset = series.get("timeOffset") if series else None
    valid_offset = (isinstance(offset, (int, float)) and not isinstance(offset, bool)
                    and math.isfinite(offset) and -12 <= offset <= 14)
    points = {}
    if series and valid_offset:
        for point in series["points"]:
            end = datetime.strptime(point["dateTime"], "%d.%m.%Y %H:%M").replace(tzinfo=MSK)
            end -= timedelta(hours=offset)
            if end in points:
                raise ValueError(f"duplicate hourly point for {contract} at {end}")
            points[end] = point.get("metrics") or {}
    for hour in full_hours(start, through):
        end = hour + HOUR
        metrics = points.get(end)
        api_votes = api_ballots = None
        if not series:
            status = "missing_contract"
        elif not valid_offset:
            status = "unknown_timezone"
        elif end > now - timedelta(minutes=lag_minutes):
            status = "not_settled"
        elif metrics is None:
            status = "missing_point"
        elif not all(isinstance(metrics.get(key), int) and not isinstance(metrics[key], bool)
                     and metrics[key] >= 0 for key in
                     ("countVote", "countBlindSign", "totalCountVote", "totalCountBlindSign")):
            status = "unpublished"
        else:
            api_votes, api_ballots = metrics["countVote"], metrics["countBlindSign"]
            status = ("match" if votes[(contract, hour)] == api_votes
                      and ballots[(contract, hour)] == api_ballots else "mismatch")
        yield dict(zip(HOURLY_COLUMNS, [
            contract, hour.isoformat(), end.isoformat(), votes[(contract, hour)], api_votes,
            None if api_votes is None else votes[(contract, hour)] - api_votes,
            ballots[(contract, hour)], api_ballots,
            None if api_ballots is None else ballots[(contract, hour)] - api_ballots,
            status, offset, now.isoformat(), start.isoformat(), through.isoformat(),
        ]))


def collect_hourly(portal, contracts, votes, ballots, start, through, *, lag_minutes=5, now=None):
    for contract in contracts:
        response = portal.get("statistics/chart/hourly?" + urlencode({"contractIds": contract}))
        series = [item for item in response["data"] if item["contractId"] == contract]
        if len(series) > 1:
            raise ValueError(f"duplicate hourly series for {contract}")
        yield from hourly_rows(contract, series[0] if series else None, votes, ballots,
                               start, through, now=now, lag_minutes=lag_minutes)


def collect_uiks(portal, contracts, page_size=100):
    """Paginate public aggregates, failing visibly if the membership shifts."""
    for contract in contracts:
        page, total, seen = 0, None, set()
        while True:
            data = portal.post("statistics/voting/uiks/search", {
                "contractId": contract, "primaryUikNumbers": None, "page": page,
                "pageSize": page_size,
                "orderBy": [{"field": "primaryUikNumber", "sortDirection": "ASC"}],
            })["data"]
            distribution = data["distributionByPrimaryUikNumbers"]
            count = distribution["totalCount"]
            if not isinstance(count, int) or count < 0 or (total is not None and count != total):
                raise ValueError(f"unstable UIK total for {contract}; retry with --refresh-cache")
            total = count
            rows = distribution["results"]
            for row in rows:
                uik = str(row["primaryUikNumber"])
                if uik in seen:
                    raise ValueError(f"duplicate UIK {uik} for {contract}; refresh and retry")
                seen.add(uik)
                yield dict(zip(UIK_COLUMNS, [contract, uik, row.get("all"), row.get("issued"),
                                            row.get("turnoutPercent"), data.get("collectionTime")]))
            if len(seen) == total:
                break
            if not rows or len(seen) > total:
                raise ValueError(f"incomplete UIK pagination for {contract}")
            page += 1


def write_report(path, rows, columns):
    # Build the small aggregate report before opening its destination so a
    # failed API page cannot leave a plausible-looking partial report.
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tables", type=Path, required=True, help="directory with existing CSV tables")
    parser.add_argument("--out", type=Path, required=True, help="report output directory")
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--api", default=API)
    parser.add_argument("--contracts", nargs="+", help="limit the report to these contract IDs")
    parser.add_argument("--hourly-from", type=moscow_time, help="declared dump start, ISO time (MSK by default)")
    parser.add_argument("--hourly-through", type=moscow_time, help="declared dump end, ISO time (MSK by default)")
    parser.add_argument("--lag-minutes", type=int, default=5, help="wait after hour end before comparing")
    parser.add_argument("--uiks", action="store_true", help="also fetch current public UIK aggregates")
    add_cache_arguments(parser)
    args = parser.parse_args(argv)
    if bool(args.hourly_from) != bool(args.hourly_through):
        parser.error("--hourly-from and --hourly-through must be supplied together")
    if not args.hourly_from and not args.uiks:
        parser.error("select an hourly interval and/or --uiks")
    if args.lag_minutes < 0:
        parser.error("--lag-minutes must be nonnegative")
    if args.hourly_from and not list(full_hours(args.hourly_from, args.hourly_through)):
        parser.error("the declared interval must contain at least one full clock hour")
    contracts, votes, ballots = read_tables(
        args.tables, args.hourly_from, args.hourly_through,
        set(args.contracts) if args.contracts else None,
    )
    with Portal(args.cache or args.out / "cache", base=args.api,
                cache_ttl=args.cache_ttl, refresh_cache=args.refresh_cache) as portal:
        if args.hourly_from:
            rows = write_report(args.out / "hourly_comparison.csv", collect_hourly(
                portal, contracts, votes, ballots, args.hourly_from, args.hourly_through,
                lag_minutes=args.lag_minutes,
            ), HOURLY_COLUMNS)
            print(f"hourly status counts: {dict(Counter(row['status'] for row in rows))}")
        if args.uiks:
            rows = write_report(args.out / "portal_uiks.csv", collect_uiks(portal, contracts), UIK_COLUMNS)
            print(f"UIK rows: {len(rows)}")
        print(f"API calls: {portal.calls}, cache hits: {portal.cache_hits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
