"""Deterministic primitive regressions and tiny, immutable 2025 export controls."""
import base64
import contextlib
import copy
import io
import json
import random
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from crypto import bulletin, cli, curve, elgamal, hashfn, protocol, streebog, tezhu, zkp

FIXTURES = Path(__file__).resolve().parent / 'fixtures'
ONE = FIXTURES / '4BbdvzVdbyQES6ARbt4YDB4htfUYgwUVGpQYNa6dLj3u.zip'
FOUR = FIXTURES / '9efgbWtn68NP41wXJutPMYgCLoUgnyEEZvpr9KgYVPb5.zip'


def range_cell(pk, message, randomness, messages):
    """Generate an honest disjunctive proof with deterministic test-only nonces."""
    a = curve.mul_generator(randomness)
    b = curve.add(curve.mul(pk, randomness), curve.mul_generator(message))
    cs, rs, aa, bb = [], [], [], []
    nonce = 101
    for index, value in enumerate(messages):
        c, r = index + 7, index + 19
        shifted = curve.sub(b, curve.mul_generator(value))
        aa.append(curve.mul_generator(nonce) if value == message else curve.mul_add(r, curve.G, -c, a))
        bb.append(curve.mul(pk, nonce) if value == message else curve.mul_add(r, pk, -c, shifted))
        cs.append(c)
        rs.append(r)
    i = messages.index(message)
    cs[i] = (hashfn.points_hash_mod_q([pk, a, b] + aa + bb) - sum(cs) + cs[i]) % curve.Q
    rs[i] = (nonce + cs[i] * randomness) % curve.Q
    return bulletin.RangeProof(curve.compress(a), curve.compress(b),
            list(map(curve.compress, aa)), list(map(curve.compress, bb)),
            [c.to_bytes(32, 'big') for c in cs], [r.to_bytes(32, 'big') for r in rs])


class PrimitiveTests(unittest.TestCase):
    def test_streebog_vectors(self):
        # RFC 6986 displayed vectors reversed into the byte-oriented library convention.
        vectors = [(b'012345678901234567890123456789012345678901234567890123456789012',
                    '9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500'),
                   ('Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы'.encode('cp1251'),
                    '9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50')]
        for message, digest in vectors:
            self.assertEqual(streebog.streebog256(message).hex(), digest)
        self.assertEqual(hashfn.DST_BLIND_ROP, hashfn.DST_BLIND + bytes([80]))

    def test_production_hash_trace_known_answer(self):
        trace = json.loads((FIXTURES / 'decryption-challenge.json').read_text())
        dst = bytes.fromhex(trace['dst_hex'])
        self.assertEqual(dst, hashfn.DST_DP)
        message = b''.join(bytes.fromhex(p) for p in trace['transcript_parts_hex'])
        scalar = int.from_bytes(hashfn.xmd_ro(message, dst + bytes([len(dst)])), 'big') % curve.Q
        self.assertEqual(scalar.to_bytes(32, 'little').hex(), trace['challenge_le_hex'])
        state = protocol.contract_state(protocol.load_export(ONE))
        self.assertEqual(bytes.fromhex(trace['transcript_parts_hex'][0]).decode(), state['VOTING_BASE']['pollId'])

    def test_noncanonical_public_key(self):
        self.assertEqual(curve.from_le_xy(curve.to_le_xy(curve.G)), curve.G)
        with self.assertRaises(ValueError):
            curve.from_le_xy((curve.P + 1).to_bytes(32, 'little') + curve.GY.to_bytes(32, 'little'))

    def test_tezhu_zero_y_forgery_and_positive(self):
        message = b'test-voter'
        challenge = int.from_bytes(hashfn.xmd_ro(curve.to_le_xy(curve.G) * 2 + message,
                                   hashfn.DST_BLIND_ROP), 'big') % curve.Q
        encode = lambda values: b''.join(v.to_bytes(32, 'little') for v in values)
        for x, z in [(11, 13), (23, 29)]:
            key = curve.to_le_xy(curve.mul_generator(x)) + curve.to_le_xy(curve.mul_generator(z))
            for y in [0, curve.Q]:
                self.assertFalse(tezhu.verify(key, message, encode([challenge, 1, y, 1])))
            y, a, b = 17, 31, 37
            c = int.from_bytes(hashfn.xmd_ro(curve.to_le_xy(curve.mul_generator(a)) +
                curve.to_le_xy(curve.mul_generator(b)) + message, hashfn.DST_BLIND_ROP), 'big') % curve.Q
            signature = [c, (a + c * y * x) % curve.Q, y, (b - y * z) % curve.Q]
            self.assertTrue(tezhu.verify(key, message, encode(signature)))
            self.assertFalse(tezhu.verify(key, message + b'x', encode(signature)))
            for index in [0, 1, 3]:
                bad = signature.copy(); bad[index] = curve.Q
                self.assertFalse(tezhu.verify(key, message, encode(bad)))

    def test_dlp_duplicates_opposites_and_batch_boundaries(self):
        self.assertEqual(elgamal.solve_dlp_batch([curve.G, curve.G, None, None], 1),
                         {0: 1, 1: 1, 2: 0, 3: 0})
        self.assertEqual(elgamal.solve_dlp_batch([curve.neg(curve.G), curve.G], 1), {0: None, 1: 1})
        values = [0, 1, 2, 127, 128, 129, 256]
        points = [curve.mul_generator(v) for v in values]
        self.assertEqual(elgamal.solve_dlp_batch(points, 256), dict(enumerate(values)))
        self.assertEqual(elgamal.solve_dlp_batch([], 0), {})
        with self.assertRaises(ValueError): elgamal.solve_dlp_batch([], -1)

    def test_jacobian_sum_and_shamir(self):
        points = [curve.mul_generator(n) for n in [1, 2, 3, 7]]
        ballots = [[[(p, curve.neg(p)), (None, p)]] for p in points]
        expected = curve.mul_generator(13)
        self.assertEqual(elgamal.add(ballots), [[(expected, curve.neg(expected)), (None, expected)]])
        self.assertEqual(curve.mul_add(17, points[0], -29, points[1]),
                         curve.add(curve.mul(points[0], 17), curve.mul(points[1], -29)))
        with self.assertRaises(ValueError): elgamal.add([ballots[0], [[]]])

    def test_arithmetic_against_affine_reference(self):
        rng = random.Random(20250914)
        for _ in range(8):
            p = curve.mul_affine(curve.G, rng.randrange(1, 100))
            q = curve.mul_affine(curve.G, rng.randrange(1, 100))
            a, b = (rng.randrange(-curve.Q, curve.Q) for _ in range(2))
            expected = curve.add_affine(curve.mul_affine(p, a), curve.mul_affine(q, b))
            self.assertEqual(curve.mul_add(a, p, b, q), expected)
            self.assertEqual(curve.mul(p, a), curve.mul_affine(p, a))
            self.assertEqual(curve.mul_generator(a), curve.mul_affine(curve.G, a))
            self.assertEqual(curve.add_many([p, None, q, curve.neg(p)]), q)
        expected = None
        for actual in curve.generator_walk(257):
            self.assertEqual(actual, expected)
            expected = curve.add_affine(expected, curve.G)

    def test_range_proof_and_linkage(self):
        pk = curve.mul_generator(13)
        tx = next(t for t in protocol.load_export(ONE) if t.accepted_vote())
        for values, linked in [([1, 0], True), ([1, 1], False), ([0, 0], False)]:
            options = [range_cell(pk, value, r, [0, 1]) for value, r in zip(values, [11, 17])]
            total = range_cell(pk, 1, 28 if linked else 37, [1])
            for proof in options:
                self.assertTrue(zkp.verify_range_proof(pk, [0, 1], vars(proof)))
            self.assertTrue(zkp.verify_range_proof(pk, [1], vars(total)))
            result = protocol.AuditResult()
            with patch.object(bulletin, 'decode_bulletin', return_value=[bulletin.Question(options, total)]):
                value = protocol._ballot(tx, pk, b'', [[1, 1, 2]], result, b'', True, False)
            self.assertEqual(value is not None, linked)
            self.assertEqual(bool(result.bad_zkp), not linked)
        proof = vars(options[0]); proof['c'] = []
        with self.assertRaises(zkp.ProofError): zkp.verify_range_proof(pk, [0, 1], proof)

    def test_malformed_protobuf(self):
        for value in [b'\x0a\x08\x00', b'\x80', b'\x00', b'\x80' * 11, b'\x80' * 9 + b'\x02']:
            with self.assertRaises(ValueError): bulletin.decode_bulletin(value)


class AuditTests(unittest.TestCase):
    def audit_txs(self, txs, **kwargs):
        with patch.object(protocol, 'load_export', return_value=txs):
            return protocol.audit(ONE, **kwargs)

    def test_real_complete_and_sampling(self):
        result = protocol.audit(ONE)
        self.assertEqual(result.verdict, 'verified', result.summary())
        self.assertTrue(all(result.partial_decryption_ok.values()))
        full = protocol.audit(FOUR)
        self.assertEqual(full.verdict, 'verified', full.summary())
        sample = protocol.audit(FOUR, max_votes=1)
        self.assertEqual((sample.verdict, sample.checked_ballots, sample.accepted), ('incomplete', 1, 4))
        self.assertIsNone(sample.results_match)
        self.assertEqual(sample.partial_decryption_ok, {})
        for flag in ['verify_tx_signatures', 'check_proofs', 'check_blind_signatures', 'check_structure']:
            result = protocol.audit(ONE, **{flag: False})
            self.assertEqual(result.verdict, 'incomplete')
        for limit in [0, -1]:
            with self.assertRaises(ValueError): protocol.audit(ONE, max_votes=limit)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cli.main(['audit', str(ONE), '--max-votes', str(limit)])

    def test_production_decryption_context_commitment_response_mutations(self):
        txs = protocol.load_export(ONE); state = protocol.contract_state(txs)
        vote = next(t for t in txs if t.accepted_vote())
        questions = bulletin.decode_bulletin(base64.b64decode(vote.param('vote')))
        for table, key in zip(protocol._decryption_tables(state), ['DKG_KEY', 'COMMISSION_KEY']):
            pk = curve.decompress(bytes.fromhex(state[key]))
            for q, row in enumerate(table):
                for c, proof in enumerate(row):
                    cell = questions[q].options[c]
                    cipher = curve.decompress(cell.A), curve.decompress(cell.B)
                    poll = state['VOTING_BASE']['pollId']
                    self.assertTrue(zkp.verify_decryption(pk, cipher, proof, poll_id=poll))
                    self.assertFalse(zkp.verify_decryption(pk, cipher, proof, poll_id=poll + 'x'))
                    self.assertFalse(zkp.verify_decryption(curve.G, cipher, proof, poll_id=poll))
                    self.assertFalse(zkp.verify_decryption(pk, (curve.G, cipher[1]), proof, poll_id=poll))
                    for field in ['P', 'U1', 'U2', 'w']:
                        bad = proof.copy()
                        bad[field] = ('01'.rjust(64, '0') if field == 'w' else curve.compress(curve.G).hex())
                        self.assertFalse(zkp.verify_decryption(pk, cipher, bad, poll_id=poll))
                    swapped = dict(proof, U1=proof['U2'], U2=proof['U1'])
                    self.assertFalse(zkp.verify_decryption(pk, cipher, swapped, poll_id=poll))

    def test_vote_write_rollback_and_commission_state(self):
        txs = protocol.load_export(ONE)
        commission = next(t for t in txs if t.operation == 'commissionDecryption')
        expected = protocol.contract_state(txs)['COMMISSION_DECRYPTION']
        for diff in [[], [{'key': 'FAIL_bad', 'stringValue': 'no'}], commission.diff]:
            rejected = copy.deepcopy(commission); rejected.diff = diff
            for p in rejected.params:
                if p['key'] == 'decryption': p['stringValue'] = 'bad'
            if diff == commission.diff: rejected.rollback = '-1'
            self.assertEqual(protocol.contract_state(txs + [rejected])['COMMISSION_DECRYPTION'], expected)
        vote = next(t for t in txs if t.accepted_vote())
        for rollback in [False, True]:
            changed = copy.deepcopy(txs)
            v = next(t for t in changed if t.tx_id == vote.tx_id)
            if rollback: v.rollback = '-1'
            else: v.diff = []
            result = self.audit_txs(changed, verify_tx_signatures=False)
            self.assertEqual(result.accepted, 0)
            self.assertEqual(result.checked_ballots, 0)
            self.assertFalse(result.results_match)  # published one vote, empty accepted set
            self.assertEqual(result.verdict, 'failed')

    def test_malformed_and_missing_election_data(self):
        txs = protocol.load_export(ONE)
        for mode in ['key', 'protobuf', 'fee', 'decryption', 'results', 'missing-results', 'missing-decryption']:
            changed = copy.deepcopy(txs)
            vote = next(t for t in changed if t.accepted_vote())
            if mode == 'key': vote.sender = '0'; vote.diff[0]['key'] = 'VOTE_0'
            elif mode == 'fee': vote.fee = '1'
            elif mode == 'protobuf':
                for p in vote.params:
                    if p['key'] == 'vote': p['binaryValue'] = base64.b64encode(b'\x80').decode()
            elif mode in ['decryption', 'missing-decryption']:
                tx = next(t for t in changed if t.operation == 'commissionDecryption')
                if mode == 'missing-decryption': changed.remove(tx)
                else:
                    for p in tx.params:
                        if p['key'] == 'decryption': p['stringValue'] = '[]'
            else:
                tx = next(t for t in changed if t.operation == 'results')
                if mode == 'missing-results': changed.remove(tx)
                else:
                    for entry in tx.diff:
                        if entry['key'] == 'RESULTS': entry['stringValue'] = 'bad'
            result = self.audit_txs(changed, verify_tx_signatures=mode in ['key', 'fee'])
            self.assertEqual(result.verdict, 'incomplete' if mode.startswith('missing') else 'failed', (mode, result.summary()))
        with patch.object(protocol, 'load_export', side_effect=RuntimeError('bug')):
            with self.assertRaises(RuntimeError): protocol.audit(ONE)

    def test_malformed_string_values_are_attributed_and_batch_continues(self):
        with zipfile.ZipFile(ONE) as source:
            original = source.read(source.namelist()[0]).decode().splitlines()
        for field in ['image', 'imageHash', 'contractName', 'stringValue', 'feeAssetId']:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                lines = original.copy()
                index = next(i for i, line in enumerate(lines) if line.split(';')[1] == '103')
                columns = lines[index].split(';')
                if field == 'stringValue':
                    entries = json.loads(columns[8])
                    next(e for e in entries if 'stringValue' in e)['stringValue'] = 123
                    columns[8] = json.dumps(entries)
                elif field == 'feeAssetId':
                    # CSV fields are always strings; exercise the serializer directly.
                    tx = next(t for t in protocol.load_export(ONE) if t.type == 103)
                    with self.assertRaisesRegex(ValueError, 'feeAssetId must be a string'):
                        bulletin.transaction_bytes(dict(type=tx.type, version=tx.version,
                            ts=tx.ts, senderPublicKey=tx.sender, params=tx.params,
                            extra=tx.extra, feeAssetId=123))
                    continue
                else:
                    extra = json.loads(columns[10]); extra[field] = 123
                    columns[10] = json.dumps(extra)
                lines[index] = ';'.join(columns)
                bad = Path(temp) / ONE.name
                with zipfile.ZipFile(bad, 'w') as archive:
                    archive.writestr(ONE.stem + '.csv', '\n'.join(lines))
                result = protocol.audit(bad)
                self.assertEqual(result.verdict, 'failed')
                self.assertIn(columns[0], result.wrong_tx_signature)
                self.assertTrue(any('must be a string' in note for note in result.notes))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(cli.main(['audit', str(bad), str(ONE)]), 1)
                self.assertIn('verdict: verified', output.getvalue())

    def test_batch_continues_and_exit_verdict(self):
        valid = protocol.audit(ONE)
        cases = [valid]
        for name in ['key_aggregation_ok', 'results_match']:
            result = copy.deepcopy(valid); setattr(result, name, False); cases.append(result)
        for name in valid.partial_decryption_ok:
            result = copy.deepcopy(valid); result.partial_decryption_ok[name] = False; cases.append(result)
        result = copy.deepcopy(valid); result.results_match = None; cases.append(result)
        for i, result in enumerate(cases):
            with patch.object(protocol, 'audit', return_value=result), contextlib.redirect_stdout(io.StringIO()):
                code = cli.main(['audit', str(ONE)])
            self.assertEqual(code, 0 if i == 0 else 2 if i == len(cases)-1 else 1)
        with tempfile.TemporaryDirectory() as temp:
            bad = Path(temp) / 'bad.csv'; bad.write_text('malformed')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = cli.main(['audit', str(bad), str(ONE)])
            self.assertEqual(code, 1)
            self.assertIn('verdict: verified', output.getvalue())
            self.assertIn('verdict: failed', output.getvalue())

    def test_probe_same_sample_all_conventions(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output): code = cli.main(['probe-tx', str(ONE), '--limit', '2'])
        self.assertEqual(code, 0)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertTrue(all('/2 signatures' in line for line in lines))
        self.assertTrue(lines[-1].endswith('2/2 signatures verify'))
        self.assertTrue(all('0/2 signatures' in line for line in lines[:-1]))


if __name__ == '__main__':
    unittest.main()
