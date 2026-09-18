"""Offline regressions for public metadata, cache freshness and hour semantics."""

import copy
import csv
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from datetime import timedelta
from unittest.mock import Mock, patch

import requests

PARSER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PARSER))
from portal import Portal, collect_federal_metadata
from portal_reports import (collect_hourly, collect_uiks, hourly_rows, moscow_time,
                            read_tables, write_report, HOURLY_COLUMNS)

spec = importlib.util.spec_from_file_location("deg_parser", PARSER / "parse.py")
parse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse)

FIXTURES = json.loads((Path(__file__).parent / "fixtures/portal.json").read_text(encoding="utf-8"))
CONTRACT = "CJ9vdyteoijMZrUXjhfTymUGP6JMvtKppdQ9ZxHKNoPc"
SINGLE = "FJBmtZm6wMJHFk91niNGoaKwPanyQew2XXD2VY5BXTPJ"
UNION = "7CYkHDzJvkFvbBtiFj7mtB5zfRAqP59kpGtd4TxAaJwp"
HOUR_PATH = f"statistics/chart/hourly?contractIds={CONTRACT}"


class FakePortal:
    def __init__(self):
        self.responses = copy.deepcopy(FIXTURES)
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        return self.responses[path]

    def get_many(self, paths):
        return [self.get(path) for path in paths]


class MetadataTests(unittest.TestCase):
    def test_real_shapes_preserve_both_ballots_and_leaf_counters(self):
        portal = FakePortal()
        details, counters = collect_federal_metadata(portal)
        self.assertEqual(set(details), {SINGLE, UNION})
        self.assertEqual(details[SINGLE]["ballot_type"], "SINGLE")
        self.assertEqual(details[UNION]["ballot_type"], "UNION")
        self.assertEqual(details[SINGLE]["tik"], "Арманская")
        self.assertEqual(details[SINGLE]["time_offset"], 8)
        self.assertEqual(counters[SINGLE]["all"], 57)  # Not the 8198 regional total.
        self.assertEqual(len(portal.paths), 5)

    def test_regions_come_from_statistics_not_short_elections_list(self):
        portal = FakePortal()
        portal.responses["elections?level=FEDERAL"]["data"]["elections"][0]["regions"] = []
        details, _ = collect_federal_metadata(portal)
        self.assertEqual(len(details), 2)

    def test_legacy_metadata_merge_and_explicit_skip(self):
        portal = FakePortal()
        portal.responses.update({
            "voting/regions": {"data": {"regions": [{"code": 61, "name": "ROSTOV",
                                                      "description": "Ростовская область"}]}},
            "elections/region/61/elections": {"data": {"elections": [{"elections": [
                {"electionId": "regional"}]}]}},
            "elections/districts?regionCode=61&electionId=regional": {"data": [{"id": "district"}]},
            "statistics/voting?electionId=regional&districtId=district": {"data": {
                "regionCode": 61, "electionName": "Региональные", "districtName": "Округ",
                "votings": [{"counters": {"contractId": CONTRACT, "all": 103, "issued": 53,
                                          "voted": 49}}]}},
        })
        details = {}
        names, regions, counters = parse.collect_metadata(portal, federal_details=details)
        self.assertEqual(set(names), {CONTRACT, SINGLE, UNION})
        self.assertEqual(names[CONTRACT][0], "Ростовская область")
        self.assertEqual(names[SINGLE][0], "Магаданская область")
        self.assertEqual(len(details), 2)
        portal.paths.clear()
        names, _, _ = parse.collect_metadata(portal, include_federal=False)
        self.assertEqual(set(names), {CONTRACT})
        self.assertFalse(any("v2" in p or "FEDERAL" in p for p in portal.paths))

    def test_conflicting_contract_is_not_silently_overwritten(self):
        portal = FakePortal()
        path = next(p for p in portal.responses if p.startswith("statistics/v2/election/tik?"))
        portal.responses[path]["data"]["votings"][1]["contractId"] = SINGLE
        with self.assertRaisesRegex(ValueError, "conflicting"):
            collect_federal_metadata(portal)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.client = Portal(Path(self.tmp.name))
        self.addCleanup(self.client.close)
        self.session = Mock()
        response = Mock()
        response.json.return_value = {"data": "fresh"}
        self.session.request.return_value = response
        self.client._session = Mock(return_value=self.session)

    def test_fresh_expired_refresh_zero_ttl_and_corrupt(self):
        path = "statistics/chart/hourly?contractIds=x"
        self.assertEqual(self.client.get(path), {"data": "fresh"})
        self.client.get(path)
        self.assertEqual(self.session.request.call_count, 1)
        self.assertEqual(self.client.cache_hits, 1)
        cached = self.client.path_to_file(path)
        os.utime(cached, (1, 1))
        self.client.get(path)
        self.client.refresh_cache = True
        self.client.get(path)
        self.client.refresh_cache = False
        self.client.cache_ttl = 0
        self.client.get(path)
        self.client.cache_ttl = 300
        cached.write_text("{broken")
        self.client.get(path)
        self.assertEqual(self.session.request.call_count, 5)
        self.assertEqual(list(Path(self.tmp.name).glob(".portal-*")), [])

    def test_host_query_and_post_body_are_part_of_cache_key(self):
        long_path = "statistics/" + "x" * 200
        self.assertNotEqual(self.client.path_to_file(long_path + "a"),
                            self.client.path_to_file(long_path + "b"))
        key = self.client.path_to_file("same")
        self.client.base = "https://teststat.deg.rt.ru/api"
        self.assertNotEqual(key, self.client.path_to_file("same"))
        self.assertNotEqual(self.client.path_to_file("search", "POST", {"page": 0}),
                            self.client.path_to_file("search", "POST", {"page": 1}))

    def test_failed_refresh_never_returns_stale_data(self):
        path = "elections?level=FEDERAL"
        self.client.get(path)
        self.client.refresh_cache = True
        response = requests.Response()
        response.status_code = 401
        self.session.request.side_effect = requests.HTTPError("unauthorized", response=response)
        with self.assertRaises(RuntimeError):
            self.client.get(path)
        self.assertEqual(self.session.request.call_count, 2)

    def test_invalid_cache_configuration(self):
        for ttl in (-1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                Portal(Path(self.tmp.name), cache_ttl=ttl)


class HourlyTests(unittest.TestCase):
    def setUp(self):
        self.portal = FakePortal()
        self.start = moscow_time("2026-09-18T08:00")
        self.through = moscow_time("2026-09-18T13:00")
        self.now = moscow_time("2026-09-18T15:00")
        self.votes = Counter({(CONTRACT, self.start + timedelta(hours=i)): n
                              for i, n in enumerate([8, 12, 15, 10, 4])})
        self.ballots = Counter({(CONTRACT, self.start + timedelta(hours=i)): n
                                for i, n in enumerate([9, 13, 16, 9, 6])})

    def rows(self, **kwargs):
        return list(collect_hourly(self.portal, [CONTRACT], self.votes, self.ballots,
                                  kwargs.get("start", self.start), kwargs.get("through", self.through),
                                  now=kwargs.get("now", self.now)))

    def test_real_fixture_end_labels_match_49_votes_over_five_hours(self):
        rows = self.rows()
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(row["status"] == "match" for row in rows))
        self.assertEqual(sum(row["api_votes"] for row in rows), 49)
        self.assertEqual(rows[0]["api_votes"], 8)  # 09:00 label is the 08:00 hour.

    def test_partial_hours_are_excluded_not_reported_as_missing(self):
        rows = self.rows(start=self.start + timedelta(minutes=15),
                         through=self.start + timedelta(hours=2, minutes=34))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["hour_start_msk"], "2026-09-18T09:00:00+03:00")

    def test_timezone_and_calendar_day_rollover(self):
        series = self.portal.responses[HOUR_PATH]["data"][0]
        series["timeOffset"] = 8
        for point in series["points"]:
            when = moscow_time("2026-09-18T" + point["dateTime"].split()[1]) + timedelta(hours=8)
            point["dateTime"] = when.strftime("%d.%m.%Y %H:%M")
        self.assertTrue(all(row["status"] == "match" for row in self.rows()))
        self.assertEqual(moscow_time("2026-09-18T23:00-04:00").isoformat(),
                         "2026-09-19T06:00:00+03:00")

    def test_placeholder_zeros_are_unpublished(self):
        rows = self.rows(through=moscow_time("2026-09-18T14:00"))
        self.assertEqual(rows[-1]["status"], "unpublished")
        self.assertIsNone(rows[-1]["api_votes"])
        self.assertIsNone(rows[-1]["votes_delta"])

    def test_missing_contract_point_timezone_and_settlement(self):
        self.portal.responses[HOUR_PATH]["data"] = []
        self.assertEqual(self.rows()[0]["status"], "missing_contract")
        self.portal = FakePortal()
        series = self.portal.responses[HOUR_PATH]["data"][0]
        series["points"] = []
        self.assertEqual(self.rows()[0]["status"], "missing_point")
        del series["timeOffset"]
        self.assertEqual(self.rows()[0]["status"], "unknown_timezone")
        self.portal = FakePortal()
        self.assertEqual(self.rows(now=self.start + timedelta(hours=1, minutes=2))[0]["status"],
                         "not_settled")

    def test_mismatch_and_true_published_zero(self):
        self.votes[(CONTRACT, self.start)] -= 1
        row = self.rows()[0]
        self.assertEqual((row["status"], row["votes_delta"]), ("mismatch", -1))
        self.portal.responses[HOUR_PATH]["data"][0]["points"][1]["metrics"] = {
            "countVote": 0, "countBlindSign": 0, "totalCountVote": 0, "totalCountBlindSign": 0}
        self.votes[(CONTRACT, self.start)] = self.ballots[(CONTRACT, self.start)] = 0
        self.assertEqual(self.rows()[0]["status"], "match")

    def test_duplicate_hour_fails(self):
        series = self.portal.responses[HOUR_PATH]["data"][0]
        series["points"].append(series["points"][1])
        with self.assertRaisesRegex(ValueError, "duplicate hourly"):
            self.rows()

    def test_csv_boundaries_timezone_and_unknown_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / "elections.csv").write_text("contract_id\n" + CONTRACT + "\n")
            for name in ("votes.csv", "ballots.csv"):
                (p / name).write_text("contract_id,timestamp\n" + "\n".join(
                    CONTRACT + "," + t for t in ["2026-09-18 07:59:59", "2026-09-18 08:00:00",
                                                "2026-09-18 08:59:59", "2026-09-18 09:00:00"]))
            _, votes, ballots = read_tables(p, self.start, self.start + timedelta(hours=1))
            self.assertEqual(votes[(CONTRACT, self.start)], 2)
            with self.assertRaisesRegex(ValueError, "not found"):
                read_tables(p, selected={"missing"})


class UikTests(unittest.TestCase):
    def test_pagination_preserves_missing_values_and_collection_time(self):
        fixture = FIXTURES["statistics/voting/uiks/search"]["data"]
        def post(path, body):
            self.assertEqual(path, "statistics/voting/uiks/search")
            self.assertEqual(body["contractId"], CONTRACT)
            return {"data": {"collectionTime": fixture["collectionTime"],
                             "distributionByPrimaryUikNumbers": {
                                 "totalCount": 4, "results": fixture["distributionByPrimaryUikNumbers"]
                                 ["results"][body["page"] * 2:body["page"] * 2 + 2]}}}
        portal = Mock(post=Mock(side_effect=post))
        rows = list(collect_uiks(portal, [CONTRACT], page_size=2))
        self.assertEqual([r["uik"] for r in rows], ["316", "317", "318", "319"])
        self.assertEqual(portal.post.call_count, 2)
        self.assertEqual(rows[0]["turnout_percent"], 60.71)

    def test_repeated_page_and_empty_truncated_page_fail(self):
        for results in ([{"primaryUikNumber": 1}], []):
            portal = Mock()
            portal.post.return_value = {"data": {"distributionByPrimaryUikNumbers": {
                "totalCount": 2, "results": results}}}
            with self.assertRaises(ValueError):
                list(collect_uiks(portal, [CONTRACT]))

    def test_failed_page_does_not_write_partial_report(self):
        def bad_rows():
            yield {"contract_id": CONTRACT}
            raise ValueError("incomplete")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.csv"
            with self.assertRaises(ValueError):
                write_report(path, bad_rows(), HOURLY_COLUMNS)
            self.assertFalse(path.exists())


class CliTests(unittest.TestCase):
    def test_parser_writes_federal_names_and_identity_sidecar_from_cached_api(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            with Portal(cache) as portal:
                responses = {**FIXTURES, "voting/regions": {"data": {"regions": []}}}
                for path, response in responses.items():
                    portal._store(portal.path_to_file(path), response)
            dump = root / "dump.jsonl"
            dump.write_text(json.dumps({"height": 1, "transactions": [{"type": 105, "tx": {
                "type": 104, "contractId": SINGLE, "timestamp": 1789714800000,
                "params": [{"key": "operation", "value": "vote"}],
            }}]}) + "\n")
            argv = ["parse.py", "--dump", str(dump), "--out", str(root / "out"),
                    "--cache", str(cache)]
            with patch.object(sys, "argv", argv), patch("requests.Session.request",
                                                        side_effect=AssertionError("unexpected network")):
                self.assertEqual(parse.main(), 0)
            with (root / "out/elections.csv").open(encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["region"], "Магаданская область")
            self.assertIn("Государственной Думы", rows[0]["election"])
            with (root / "out/federal_contracts.csv").open(encoding="utf-8") as stream:
                details = list(csv.DictReader(stream))
            self.assertEqual({row["ballot_type"] for row in details}, {"SINGLE", "UNION"})

    def test_skip_api_still_runs_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dump = root / "dump.jsonl"
            dump.write_text(json.dumps({"height": 1, "transactions": [{"type": 105, "tx": {
                "type": 104, "contractId": CONTRACT, "timestamp": 1789714800000,
                "params": [{"key": "operation", "value": "vote"}],
            }}]}) + "\n")
            result = subprocess.run([sys.executable, str(PARSER / "parse.py"), "--dump", str(dump),
                                     "--out", str(root / "out"), "--skip-api"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            with (root / "out/votes.csv").open() as f:
                self.assertEqual(len(list(csv.DictReader(f))), 1)
            with (root / "out/federal_contracts.csv").open() as f:
                self.assertEqual(list(csv.DictReader(f)), [])


if __name__ == "__main__":
    unittest.main()
