"""Independent equations, hostile inputs, native equivalence and streaming parity.

Nonces/private scalars below are deterministic SYNTHETIC TEST VALUES, never
production credentials. Run with each FEDDEG_EC_BACKEND (see ../AUDIT.md).
"""
import contextlib
import copy
import hashlib
import io
import json
import math
import os
import random
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from crypto import bulletin, curve, elgamal, gost3410, hashfn, protocol, stream, tezhu, zkp
from crypto.streebog import streebog256
from test_crypto import FIXTURES, ONE, FOUR, range_cell


def raw_transaction(tx, contract):
    """Transport-only conversion of immutable CSV fixtures to tiny JSONL dumps."""
    def entry(value):
        for source, kind in (("stringValue", "string"), ("binaryValue", "binary"),
                             ("intValue", "integer"), ("boolValue", "boolean")):
            if source in value:
                item = value[source]
                if kind == "binary":
                    item = "base64:" + item
                return {"key": value["key"], "type": kind, "value": item}
        raise ValueError("missing entry value")
    inner = dict(id=tx.tx_id, type=tx.type, version=tx.version, timestamp=tx.ts,
                 senderPublicKey=tx.sender, fee=int(tx.fee), feeAssetId=tx.fee_asset_id,
                 contractId=contract, proofs=[tx.signature], params=list(map(entry, tx.params)),
                 **tx.extra)
    return {"type": 105, "tx": inner, "results": list(map(entry, tx.diff))}


class ReviewTests(unittest.TestCase):
    def test_fixture_integrity(self):
        for name, digest in (
            (ONE.name, "bab7a82448bbc050cd8346e66e1a2d9a89bf816e54e8984ad2b94c0319e2f32c"),
            (FOUR.name, "c94f188468f356884f9fb7db8ea0f2b5e451f03d9552226b3b48d8fc459fc96b"),
            ("decryption-challenge.json", "7e07b529480d9da0b1dfd6fca8f2008c9c66c7b31257744754445cde61b6b105"),
        ):
            self.assertEqual(hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest(), digest)

    def test_unreduced_order_check(self):
        result = None
        # Independent affine double/add, no mul helper and no modulo-q reduction.
        for bit in bin(curve.Q)[2:]:
            result = curve.add_affine(result, result)
            if bit == "1":
                result = curve.add_affine(result, curve.G)
        self.assertIsNone(result)
        self.assertTrue(curve.check_generator_order())
        self.assertLess(curve.P + 1 + 2 * (math.isqrt(curve.P) + 1), 2 * curve.Q)
        with patch.object(curve, "Q", curve.Q + 1):
            self.assertFalse(curve.check_generator_order())

    def test_backend_arithmetic_edges(self):
        rng = random.Random(20260919)
        scalars = [0, 1, -1, curve.Q, curve.Q + 1, rng.randrange(curve.Q), 2**256 - 1]
        points = [None, curve.G, curve.neg(curve.G), curve.mul_affine(curve.G, 13)]
        for p in points:
            for scalar in scalars:
                expected = curve.mul_affine(p, scalar)
                self.assertEqual(curve.mul(p, scalar), expected)
                with patch.object(curve, "_native", None):
                    self.assertEqual(curve.mul(p, scalar), expected)
            for q in points:
                expected = curve.add_affine(p, q)
                self.assertEqual(curve.mul_add(1, p, 1, q), expected)
                with patch.object(curve, "_native", None):
                    self.assertEqual(curve.mul_add(1, p, 1, q), expected)
        self.assertEqual(curve.mul_small(curve.G, -1), curve.neg(curve.G))
        with ThreadPoolExecutor(max_workers=4) as pool:
            actual = list(pool.map(curve.mul_generator, scalars * 4))
        self.assertEqual(actual, [curve.mul_affine(curve.G, n) for n in scalars] * 4)

    def test_backend_selection_and_no_runtime_fallback(self):
        for mode, expected in (("auto", 0), ("python", 0), ("openssl", 1), ("typo", 1)):
            # Simulate an unavailable optional library without modifying the machine.
            code = ("from unittest.mock import patch\n"
                    "with patch('ctypes.util.find_library', return_value=None):\n"
                    " from crypto import curve\n assert curve.BACKEND == 'python'\n")
            result = subprocess.run([sys.executable, "-B", "-c", code],
                                    env=dict(os.environ, FEDDEG_EC_BACKEND=mode),
                                    capture_output=True, timeout=20)
            self.assertEqual(result.returncode, expected, result.stderr.decode())
        with patch.object(curve, "_native") as native:
            native.mul_add.side_effect = RuntimeError("native failure")
            with self.assertRaisesRegex(RuntimeError, "native failure"):
                curve.mul_add(1, curve.G, 1, curve.G)

    def test_point_encodings_both_paths(self):
        encodings = [b"", b"\x00", b"\x04" + bytes(32),
                     b"\x02" + curve.P.to_bytes(32, "big")]
        # Find a nonsquare x independently via Euler's criterion.
        x = next(x for x in range(100) if
                 pow((x**3 + curve.A*x + curve.B) % curve.P, (curve.P-1)//2, curve.P) == curve.P-1)
        encodings.append(b"\x02" + x.to_bytes(32, "big"))
        native = curve._native
        for backend in (None, native):
            with patch.object(curve, "_native", backend):
                for encoded in encodings:
                    with self.assertRaises(ValueError):
                        curve.decompress(encoded)
                for p in (curve.G, curve.neg(curve.G)):
                    self.assertEqual(curve.decompress(curve.compress(p)), p)
        self.assertFalse(curve.is_on_curve((curve.GX + curve.P, curve.GY)))

    def test_xmd_exact_rfc_blocks_and_point_hash_bytes(self):
        message = b"a\x00b"
        for dst in (hashfn.DST_BLIND_ROP, hashfn.DST_DP_PRIME):
            for length in (1, 32, 33, 48, 64):
                b0 = streebog256(bytes(64) + message + length.to_bytes(2, "big") + b"\0" + dst)
                b1 = streebog256(b0 + b"\x01" + dst)
                b2 = streebog256(bytes(x ^ y for x, y in zip(b0, b1)) + b"\x02" + dst)
                self.assertEqual(hashfn.xmd_ro(message, dst, length), (b1+b2)[:length])
        self.assertEqual(hashfn.xmd_ro(message), hashfn.xmd_ro(message, hashfn.DST_BLIND_ROP))
        self.assertNotEqual(hashfn.xmd_ro(message), hashfn.xmd_ro(message, hashfn.DST_BLIND))
        for length in (0, 65):
            with self.assertRaises(ValueError):
                hashfn.xmd_ro(message, length=length)
        points = [curve.G, curve.mul_affine(curve.G, 2)]
        source = "".join(f"{2+(y&1):02x}{x:064x}" for x, y in points).encode("ascii")
        self.assertEqual(hashfn.points_hash(points), int.from_bytes(streebog256(source), "big"))

    def test_gost_equations_zero_digest_and_invalid_keys(self):
        secret, nonce = 13, 17
        key = curve.mul_affine(curve.G, secret)
        r = curve.mul_affine(curve.G, nonce)[0] % curve.Q
        for digest in (bytes(32), bytes(range(32))):
            e = int.from_bytes(digest, "little") % curve.Q or 1
            s = (r*secret + nonce*e) % curve.Q
            signature = s.to_bytes(32, "big") + r.to_bytes(32, "big")
            with patch.object(gost3410, "streebog256", return_value=digest):
                self.assertTrue(gost3410.verify(key, b"message", signature))
                for bad_key in (None, (1, 1), (key[0]+curve.P, key[1])):
                    self.assertFalse(gost3410.verify(bad_key, b"message", signature))
                for value in (0, curve.Q, 2**256-1):
                    self.assertFalse(gost3410.verify(key, b"message", value.to_bytes(32, "big") + signature[32:]))
                    self.assertFalse(gost3410.verify(key, b"message", signature[:32] + value.to_bytes(32, "big")))
        # sG-rPK=O, even though both scalars are nonzero.
        signature = secret.to_bytes(32, "big") + (1).to_bytes(32, "big")
        self.assertFalse(gost3410.verify(key, b"message", signature))

    def test_range_reference_and_mutations(self):
        pk = curve.mul_affine(curve.G, 13)
        for messages, message in (([0, 1], 0), ([0, 1], 1), ([1], 1), ([0, 1, 2, 3], 2)):
            cell = vars(range_cell(pk, message, 11, messages))
            self.assertTrue(zkp.verify_range_proof(pk, messages, cell))
            a, b = (curve.decompress(cell[k]) for k in ("A", "B"))
            for index, m in enumerate(messages):
                c, r = (int.from_bytes(cell[k][index], "big") for k in ("c", "r"))
                # Direct RHS equations, not the optimized rearrangement.
                aa, bb = (curve.decompress(cell[k][index]) for k in ("As", "Bs"))
                self.assertEqual(curve.mul_affine(curve.G, r),
                                 curve.add_affine(aa, curve.mul_affine(a, c)))
                shifted = curve.add_affine(b, curve.neg(curve.mul_affine(curve.G, m)))
                self.assertEqual(curve.mul_affine(pk, r),
                                 curve.add_affine(bb, curve.mul_affine(shifted, c)))
            for field in ("As", "Bs", "c", "r"):
                bad = copy.deepcopy(cell)
                bad[field][0] = ((1).to_bytes(32, "big") if field in ("c", "r") else curve.compress(curve.G))
                self.assertFalse(zkp.verify_range_proof(pk, messages, bad))
            for field in ("c", "r"):
                for value in (0, curve.Q, 2**256-1):
                    bad = copy.deepcopy(cell)
                    bad[field][0] = value.to_bytes(32, "big")
                    self.assertFalse(zkp.verify_range_proof(pk, messages, bad))
                bad = copy.deepcopy(cell)
                bad[field][0] = b"\x01"
                with self.assertRaises(zkp.ProofError):
                    zkp.verify_range_proof(pk, messages, bad)
        cell = vars(range_cell(pk, 1, 11, [0, 1]))
        for messages in ([], [0, 0], [-1, 0], [0, curve.Q]):
            with self.assertRaises(zkp.ProofError):
                zkp.verify_range_proof(pk, messages, cell)
        self.assertFalse(zkp.verify_range_proof(pk, [1, 0], cell))
        self.assertFalse(zkp.verify_range_proof(None, [0, 1], cell))
        # Keep sum(c) constant: this MUST fail an equation, not just the hash.
        values = [int.from_bytes(v, "big") for v in cell['c']]
        cell['c'] = [((values[0]+1) % curve.Q).to_bytes(32, 'big'),
                     ((values[1]-1) % curve.Q).to_bytes(32, 'big')]
        self.assertFalse(zkp.verify_range_proof(pk, [0, 1], cell))

    def test_zero_tezhu_challenge_and_decryption_scalar_rules(self):
        key = curve.to_le_xy(curve.G) * 2
        signature = b"".join(v.to_bytes(32, "little") for v in (0, 1, 1, 1))
        with patch.object(tezhu, "xmd_ro", return_value=bytes(48)):
            self.assertFalse(tezhu.verify(key, b"test", signature))
        secret, challenge = 13, 19
        a = curve.mul_affine(curve.G, 17)
        pk = curve.mul_affine(curve.G, secret)
        nonce = (-challenge*secret) % curve.Q
        proof = {"P": curve.compress(curve.mul_affine(a, secret)),
                 "U1": curve.compress(curve.mul_affine(a, nonce)),
                 "U2": curve.compress(curve.mul_affine(curve.G, nonce)), "w": bytes(32)}
        with patch.object(zkp, "xmd_ro", return_value=challenge.to_bytes(48, "big")):
            self.assertTrue(zkp.verify_decryption(pk, (a, None), proof, poll_id="test"))
            for value in (curve.Q, 2**256-1):
                self.assertFalse(zkp.verify_decryption(pk, (a, None),
                                 dict(proof, w=value.to_bytes(32, "big")), poll_id="test"))
        with self.assertRaises(zkp.ProofError):
            zkp.verify_decryption(pk, (None, None), proof, poll_id="test")

    def test_key_weights_and_bounded_tally(self):
        state = protocol.contract_state(protocol.load_export(ONE))
        p1, p2, main = (curve.decompress(bytes.fromhex(state[k]))
                        for k in ("DKG_KEY", "COMMISSION_KEY", "MAIN_KEY"))
        h1, h2 = hashfn.points_hash_mod_q([p1, p2]), hashfn.points_hash_mod_q([p2, p1])
        expected = curve.add_affine(curve.mul_affine(p1, h1), curve.mul_affine(p2, h2))
        self.assertEqual(main, expected)
        self.assertNotEqual(main, curve.mul_add(h2, p1, h1, p2))  # PDF's reversed assignment.
        self.assertEqual(elgamal.key_agg(p1, p2), expected)
        for limit in (None, -1, curve.Q, True):
            with self.assertRaises(ValueError):
                elgamal.solve_dlp(curve.G, limit)
        with self.assertRaises(ValueError):
            elgamal.dec_agg([(curve.G, curve.G)], [], p1, p2, limit=1)
        self.assertIsNone(elgamal.solve_dlp(curve.mul_generator(2), 1))


class StreamingTests(unittest.TestCase):
    def run_dump(self, transactions, contract, *, workers=1, results_only=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.jsonl"
            path.write_text(json.dumps({"transactions": [raw_transaction(tx, contract)
                                                       for tx in transactions]}) + "\n")
            verifier = stream.StreamVerifier(workers, results_only)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = verifier.run(path)
            return code, verifier.completed, output.getvalue()

    def test_batch_stream_worker_and_results_only_parity(self):
        for fixture in (ONE, FOUR):
            txs = protocol.load_export(fixture)
            expected = protocol.audit(fixture)
            for workers, results_only in ((1, False), (2, False), (2, True)):
                code, results, output = self.run_dump(txs, fixture.stem, workers=workers,
                                                      results_only=results_only)
                self.assertEqual(code, 0, output)
                self.assertEqual(len(results), 1)
                result = results[0]
                self.assertEqual(result.tally, expected.tally)
                self.assertEqual(result.partial_decryption_ok, expected.partial_decryption_ok)
                self.assertTrue(result.final_result_verified)
                self.assertEqual(result.verdict, "incomplete" if results_only else "verified")
                self.assertEqual(result.checked_ballots, result.valid_bulletins)

    def test_failure_totals_empty_input_and_revotes(self):
        txs = protocol.load_export(ONE)
        txs[0].signature = "1"
        code, results, output = self.run_dump(txs, ONE.stem)
        self.assertEqual(code, 1)
        self.assertEqual(results[0].verdict, "failed")
        self.assertIn("verified=0; failed=1; incomplete=0", output)
        for results_only in (False, True):
            self.assertEqual(self.run_dump([], ONE.stem, results_only=results_only)[0], 2)
        txs = protocol.load_export(ONE)
        vote = next(tx for tx in txs if tx.accepted_vote())
        txs.insert(txs.index(vote)+1, copy.deepcopy(vote))
        code, results, _ = self.run_dump(txs, ONE.stem)
        self.assertEqual(code, 1)
        self.assertTrue(results[0].revotes)
        self.assertIsNone(results[0].results_match)

    def test_benchmark_uses_full_election_and_checks_return_values(self):
        import bench
        seed = bench.load_seed(FOUR)
        self.assertTrue(zkp.verify_decryption(seed['pk1'], seed['summed_cell'],
                        seed['master_cell'], poll_id=seed['poll_id']))
        with self.assertRaises(ValueError):
            bench.timed(lambda: False, 1)


if __name__ == "__main__":
    unittest.main()
