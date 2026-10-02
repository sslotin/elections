import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from crypto import protocol
from crypto.stream import BallotScheduler, Election, StreamVerifier, dump_size, iter_dump_lines


class CompressedChunkDirectoryTests(unittest.TestCase):
    def test_reads_sorted_gzip_chunks_and_ignores_state_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = b'{"height":1}\n'
            second = b'{"height":2}\n'
            with gzip.open(root / "000000001-000000001.jsonl.gz", "wb") as stream:
                stream.write(first)
            with gzip.open(root / "000000002-000000002.jsonl.gz", "wb") as stream:
                stream.write(second)
            (root / "state.json").write_text(json.dumps({"height": 2}), encoding="utf-8")

            positions = []
            lines = list(iter_dump_lines(root, positions.append))

            self.assertEqual(lines, [first.decode(), second.decode()])
            self.assertEqual(positions, sorted(positions))
            self.assertEqual(positions[-1], len(first) + len(second))
            self.assertIsNone(dump_size(root))


class ResultsOnlyOrderingTests(unittest.TestCase):
    @staticmethod
    def tx(tx_id, operation, *, sender="server", diff=(), extra_params=()):
        return protocol.Transaction(
            tx_id=tx_id, type=104, signature="", version=4, ts=1,
            sender=sender, fee="0", fee_asset_id="",
            params=[{"key": "operation", "stringValue": operation}, *extra_params],
            diff=list(diff), extra={}, rollback="",
        )

    def test_waits_for_both_decryption_shares_after_results(self):
        election = Election("contract", False, False, False, results_only=True)
        scheduler = BallotScheduler(1)
        try:
            election.process(self.tx("results", "results", diff=[
                {"key": "RESULTS", "stringValue": "[]"},
            ]), scheduler)
            self.assertFalse(election.ready_to_finalize())

            election.process(self.tx("master", "decryption", diff=[
                {"key": "DECRYPTION_server", "stringValue": "{}"},
            ], extra_params=[{"key": "decryption", "stringValue": "{}"}]), scheduler)
            self.assertFalse(election.ready_to_finalize())

            election.process(self.tx("commission", "commissionDecryption", diff=[
                {"key": "COMMISSION_DECRYPTION", "stringValue": "{}"},
            ], extra_params=[{"key": "decryption", "stringValue": "{}"}]), scheduler)
            self.assertTrue(election.ready_to_finalize())
        finally:
            scheduler.shutdown()

    def test_prior_failed_ballot_is_excluded_from_result_only_sum(self):
        tx_id = "known-invalid"
        election = Election(
            "contract", False, False, False, results_only=True,
            excluded_ballots={tx_id: "failed full audit"},
        )
        scheduler = BallotScheduler(1)
        try:
            election.process(self.tx(tx_id, "vote", sender="voter", diff=[
                {"key": "VOTE_voter", "stringValue": "accepted"},
            ]), scheduler)
        finally:
            scheduler.shutdown()

        self.assertEqual(election.result.accepted, 1)
        self.assertEqual(election.result.checked_ballots, 1)
        self.assertEqual(election.result.valid_bulletins, 0)
        self.assertEqual(election.result.excluded_ballots, {tx_id: "failed full audit"})
        self.assertFalse(election.pending_votes)

    def test_results_only_tally_gate_allows_only_explicit_exclusions(self):
        result_only = Election("contract", False, False, False, results_only=True)
        result_only.result.accepted = 1
        result_only.result.valid_bulletins = 0
        result_only.result.excluded_ballots["invalid"] = "failed full audit"
        self.assertTrue(result_only.ballot_aggregate_complete())

        full_audit = Election("contract", True, True, True)
        full_audit.result.accepted = 1
        full_audit.result.valid_bulletins = 0
        full_audit.result.excluded_ballots["invalid"] = "failed full audit"
        self.assertFalse(full_audit.ballot_aggregate_complete())

    def test_result_phase_accepts_explicitly_excluded_ballot(self):
        result = protocol.AuditResult(
            accepted=1, checked_ballots=1, valid_bulletins=0,
            excluded_ballots={"known-invalid": "failed full audit"},
            key_aggregation_ok=True,
            partial_decryption_ok={"Учетчик": True, "Комиссия": True},
            results_match=True,
        )
        self.assertTrue(result.final_result_verified)

    def test_stream_replays_decryption_shares_after_results(self):
        transactions = [
            self.tx("results", "results", diff=[
                {"key": "RESULTS", "stringValue": "[]"},
            ]),
            self.tx("master", "decryption", diff=[
                {"key": "DECRYPTION_server", "stringValue": "{}"},
            ], extra_params=[{"key": "decryption", "stringValue": "{}"}]),
            self.tx("commission", "commissionDecryption", diff=[
                {"key": "COMMISSION_DECRYPTION", "stringValue": "{}"},
            ], extra_params=[{"key": "decryption", "stringValue": "{}"}]),
        ]
        block = json.dumps({"transactions": [
            {"tx": {"contractId": "contract"}} for _ in transactions
        ]})
        verifier = StreamVerifier(1, results_only=True)
        with (patch("crypto.stream.dump_size", return_value=len(block)),
              patch("crypto.stream.iter_dump_lines", return_value=iter([block])),
              patch("crypto.stream.transaction_from_raw", side_effect=transactions)):
            verifier.run(Path("unused.jsonl"))

        self.assertEqual(verifier.input_anomalies, 0)
        self.assertEqual(len(verifier.completed), 1)
        self.assertEqual(verifier.completed[0].transactions, 3)


if __name__ == "__main__":
    unittest.main()
