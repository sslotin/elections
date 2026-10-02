"""Audit of one voting, following protocol2023.pdf §4.6 ("Аудит").

For every voting of the export the observer checks:

1. the transaction signature S.Verify (GOST R 34.10-2012) of every exported
   contract request, including contract-rejected requests (§4.4.1);
2. the blind signature BS.Verify of the voter's key on every bulletin (§4.4.1);
3. the shape of the bulletin: `dimension` cells (t options), 𝑚ᵢ ∈ {0,1} and
   min ≤ Σ𝑚ᵢ ≤ max (§4.2.2, §4.4.1);
4. the zero-knowledge proofs of every cell: SE.VerifyEnc (§4.5.3);
5. uniqueness of the voter's verification key — "факт однократности транзакции с
   таким ключом Избирателя" (§4.4.2/§4.6);
6. that the published encryption key is the aggregation of the partial keys,
   pk = SE.KeyAgg(pk_дел, pk_недел) (§4.2.3 step 5);
7. the homomorphic sum SE.Add of the valid bulletins (§4.5.3);
8. the partial decryption proofs SE.VerifyDecPart of the Учетчик and of the
   Комиссия over that sum (§4.5.4);
9. the aggregation SE.DecAgg → results, compared with the published RESULTS
   (§4.5.4/§4.7).

Sources and independent-review map
----------------------------------
Start with ../../protocol/protocol2023.pdf §4.6, then §2.2 (gost3410.py), §2.3
(tezhu.py), §2.4 (zkp.py, elgamal.py). Those modules cite the original papers,
state the precise wire encodings, and map equations to code. The voting-system
construction is explained by Cramer, Gennaro & Schoenmakers, "A Secure and
Optimally Efficient Multi-Authority Election Scheme", EUROCRYPT '97, §§2–3:
https://crypto.ethz.ch/publications/files/CrGeSc97b.pdf
The papers justify building blocks under assumptions; they do NOT certify
this deployment. Read the raster formulas in the PDF: text extraction omits
important algorithms. Known differences from those formulas are explicitly
recorded in zkp.py and elgamal.py; `verified` means the implemented export
profile passed, NOT exact PDF conformance or a whole-election security proof.

Trace the whole acceptance chain in this order:
1. Replay accepted configuration writes; validate dimension=[min,max,t] with
   integer 0<=min<=max<=t and t>0. Authenticate the expected authority keys
   and election identifier out of band; otherwise checks use attacker-chosen
   parameters. Voting configuration is assumed immutable once ballots start.
2. Reconstruct the signed transaction bytes, check S.Verify, then BS.Verify
   over the voter's Base58 key STRING. These are independent signatures.
3. Counting follows exported state: operation=vote, rollback != '-1', no FAIL
   marker, and a VOTE_<sender> write. Reject duplicate accepted sender keys;
   do not merely count the number of vote requests or silently drop failures.
   This uniqueness check is a protocol rule (§4.4.2), not a cryptographic proof.
4. Decode each question with exactly t option cells. Check each option's {0,1}
   proof, the [min,max] proof, AND A_sum=sum(A_i), B_sum=sum(B_i). Otherwise an
   unrelated valid sum proof says nothing about this ballot's number of choices.
5. Check MAIN_KEY = KeyAgg(DKG_KEY,COMMISSION_KEY) using production coefficients.
   Sum EVERY accepted, verified ballot, not just a sample. Require all declared
   cells from both authorities, and verify both decryption proofs with pollId.
6. Unweight/subtract partials, recover each m in [0,accepted], compare every
   RESULTS cell and its shape. Failed/missing proofs or partial coverage may
   never produce a full `verified` verdict. results-only deliberately provides
   weaker evidence; record every disabled check, including sum linkage.

Trust boundary: request signatures do NOT cover exported state diffs, FAIL/
VOTE markers or block membership. We do not replay smart-contract execution,
verify consensus/block signatures, prove completeness/availability of exports,
check voter-roll eligibility or one blind-signature issuance per person, audit
DKG/secret sharing/commitments, prove honest randomness, or establish privacy,
coercion resistance or issuer unlinkability. Those parts of the PDF need
separate evidence. Empty-election decryption encodings remain unsupported and
must yield incomplete, not successful, verification. See AUDIT.md for a
reproducible review sequence and tests; synthetic tests are not security proofs.
"""

from __future__ import annotations

import base64
import json
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import bulletin, curve, elgamal, gost3410, tezhu, zkp
from .hashfn import DST_BLIND_ROP, points_hash_mod_q

STATE_OPERATIONS = {"addMainKey", "startVoting", "finishVoting", "decryption",
                    "commissionDecryption", "results"}
JSON_STATE_KEYS = {"VOTING_BASE", "VOTERS_LIST_REGISTRATORS", "SERVERS", "RESULTS"}


@dataclass
class Transaction:
    tx_id: str
    type: int
    signature: str
    version: int
    ts: int
    sender: str
    fee: str
    fee_asset_id: str
    params: list[dict]
    diff: list[dict]
    extra: dict
    rollback: str

    @property
    def operation(self) -> str:
        for entry in self.params:
            if entry["key"] == "operation":
                return str(entry.get("stringValue", ""))
        return "createContract" if self.type == 103 else ""

    def param(self, key: str):
        for entry in self.params:
            if entry["key"] == key:
                for name in ("stringValue", "binaryValue", "intValue", "boolValue"):
                    if name in entry:
                        return entry[name]
        return None

    def accepted_vote(self) -> bool:
        return (self.operation == "vote" and self.rollback != "-1" and not self.failed()
                and any(entry["key"] == "VOTE_" + self.sender for entry in self.diff))

    def failed(self) -> bool:
        return any(entry["key"].startswith("FAIL") for entry in self.diff)


@dataclass
class AuditResult:
    contract: str = ""
    transactions: int = 0
    issued: int = 0
    accepted: int = 0
    rejected: int = 0
    valid_bulletins: int = 0
    # In results-only mode, prior full-audit failures and undecodable ballots
    # are excluded from the aggregate but reported separately.
    excluded_ballots: dict[str, str] = field(default_factory=dict)
    wrong_tx_signature: list[str] = field(default_factory=list)
    bad_blind_signature: list[str] = field(default_factory=list)
    bad_shape: list[str] = field(default_factory=list)
    bad_zkp: list[str] = field(default_factory=list)
    revotes: list[str] = field(default_factory=list)
    key_aggregation_ok: bool | None = None
    partial_decryption_ok: dict[str, bool | None] = field(default_factory=dict)
    tally: list[list[int]] | None = None
    published: list[list[int]] | None = None
    results_match: bool | None = None
    error: str | None = None
    notes: list[str] = field(default_factory=list)
    enabled_checks: dict[str, bool] = field(default_factory=dict)
    checked_ballots: int = 0
    sampled: bool = False
    # Timers cover only the cryptographic phases of this audit.  They are
    # intentionally separate from parsing and conversion so benchmark output
    # can distinguish per-ballot ZKPs from final result processing.
    ballot_zkp_seconds: float = 0.0
    ballot_zkp_checks: int = 0
    result_phase_seconds: float = 0.0
    result_decryption_checks: int = 0
    aggregation_seconds: float = 0.0
    aggregation_cells: int = 0

    @property
    def final_result_verified(self) -> bool:
        """Whether the complete-election result phase passed.

        This is useful for ``--results-only``: that mode is intentionally not a
        full audit, so ``verdict`` remains ``incomplete`` even when both
        decryption proofs and the final tally are correct.
        """
        included_expected = self.accepted - len(self.excluded_ballots)
        return (not self.error and not self.sampled and
                self.checked_ballots == self.accepted and
                self.valid_bulletins == included_expected and
                self.key_aggregation_ok is True and
                self.results_match is True and
                set(self.partial_decryption_ok) == {"Учетчик", "Комиссия"} and
                all(value is True for value in self.partial_decryption_ok.values()))

    @property
    def verdict(self) -> str:
        if (self.error or self.wrong_tx_signature or self.bad_blind_signature or
                self.bad_shape or self.bad_zkp or self.revotes or
                self.key_aggregation_ok is False or self.results_match is False or
                any(value is False for value in self.partial_decryption_ok.values())):
            return "failed"
        if (not self.final_result_verified or not all(
                self.enabled_checks.get(name, False) for name in
                ("tx_signatures", "blind_signatures", "range_proofs", "ballot_structure"))):
            return "incomplete"
        return "verified"

    def summary(self) -> str:
        lines = [f"голосование {self.contract}: транзакций {self.transactions}, "
                 f"выдано подписей {self.issued}, принято {self.accepted}, "
                 f"отклонено контрактом {self.rejected}"]
        lines.append(f"  verdict: {self.verdict}; ballot coverage: {self.checked_ballots}/{self.accepted}"
                     f"; sampled: {self.sampled}; enabled checks: {self.enabled_checks}")
        lines.append(f"  действительных бюллетеней: {self.valid_bulletins}")
        if self.excluded_ballots:
            lines.append(f"  исключено бюллетеней: {len(self.excluded_ballots)}")
            lines.extend(f"    {tx_id}: {reason}" for tx_id, reason in sorted(self.excluded_ballots.items()))
        if self.enabled_checks.get("range_proofs"):
            per_ballot = (self.ballot_zkp_seconds / self.valid_bulletins
                          if self.valid_bulletins else 0.0)
            lines.append(f"  ZKP бюллетеней: {self.ballot_zkp_seconds:.3f} s, "
                         f"{self.ballot_zkp_checks} ячеек, "
                         f"{per_ballot * 1000:.3f} ms/бюллетень")
        else:
            lines.append("  Ballot checks: ПРОПУЩЕНЫ (--results-only)")
        for label, values in (("неверная подпись транзакции", self.wrong_tx_signature),
                              ("неверная слепая подпись", self.bad_blind_signature),
                              ("неверная форма бюллетеня", self.bad_shape),
                              ("неверное ZKP бюллетеня", self.bad_zkp),
                              ("повторное голосование", self.revotes)):
            lines.append(f"  {label}: {len(values)}")
        if self.key_aggregation_ok is not None:
            lines.append(f"  pk = KeyAgg(pk_дел, pk_недел): "
                         f"{'совпадает' if self.key_aggregation_ok else 'НЕ СОВПАДАЕТ'}")
        for name, value in self.partial_decryption_ok.items():
            lines.append(f"  доказательство расшифрования ({name}): "
                         f"{'unsupported' if value is None else ('корректно' if value else 'НЕКОРРЕКТНО')}")
        if self.results_match is not None:
            lines.append(f"  результаты: {'СОВПАДАЮТ' if self.results_match else 'НЕ СОВПАДАЮТ'}"
                         f"  подсчитано {self.tally} опубликовано {self.published}")
        if self.aggregation_seconds:
            lines.append(f"  гомоморфная агрегация: {self.aggregation_seconds:.3f} s "
                         f"({self.aggregation_cells} ячеек)")
        if self.result_phase_seconds:
            lines.append(f"  финальная расшифровка/результат: {self.result_phase_seconds:.3f} s "
                         f"({self.result_decryption_checks} доказательств)")
        if self.error:
            lines.append(f"  ошибка: {self.error}")
        for note in self.notes:
            lines.append(f"  примечание: {note}")
        return "\n".join(lines)


def contract_id(path: Path) -> str:
    name = path.stem
    for suffix in ("_dump", "_export"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def load_export(path: Path) -> list[Transaction]:
    """Read the portal-format CSV export (as produced by dump_to_official.py)."""
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            text = archive.read(archive.namelist()[0]).decode()
    else:
        text = path.read_text(encoding="utf-8")
    transactions = []
    for line in text.splitlines():
        if not line.strip():
            continue
        f = line.split(";")
        if len(f) != 12:
            raise ValueError(f"export line {len(transactions) + 1}: expected 12 columns")
        transactions.append(Transaction(
            tx_id=f[0], type=int(f[1]), signature=f[2], version=int(f[3]), ts=int(f[4]),
            sender=f[5], fee=f[6], fee_asset_id=f[7], params=json.loads(f[8]),
            diff=json.loads(f[9]), extra=json.loads(f[10]), rollback=f[11]))
        tx = transactions[-1]
        if (not isinstance(tx.params, list) or not isinstance(tx.diff, list) or
                not isinstance(tx.extra, dict) or any(not isinstance(entry, dict) or
                not isinstance(entry.get("key"), str) for entry in tx.params + tx.diff)):
            raise ValueError(f"malformed transaction entries: {tx.tx_id}")
    return transactions


def _entry_value(entry: dict):
    for name in ("stringValue", "binaryValue", "intValue", "boolValue"):
        if name in entry:
            return entry[name]
    return None


def contract_state(transactions: list[Transaction]) -> dict:
    """Replay the state writes of the state transactions (§4.2)."""
    state: dict = {}
    for tx in transactions:
        if tx.rollback == "-1" or tx.failed():
            continue
        if tx.operation == "decryption":
            for entry in tx.diff:
                if entry["key"].startswith("DECRYPTION_"):
                    state[entry["key"]] = tx.param("decryption")
            continue
        if tx.operation == "commissionDecryption":
            if any(entry["key"] == "COMMISSION_DECRYPTION" for entry in tx.diff):
                state["COMMISSION_DECRYPTION"] = tx.param("decryption")
            continue
        if tx.operation not in STATE_OPERATIONS and tx.type != 103:
            continue
        for entry in tx.diff:
            state[entry["key"]] = _entry_value(entry)
    for key in list(JSON_STATE_KEYS):
        value = state.get(key)
        if isinstance(value, str):
            try:
                state[key] = json.loads(value)
            except json.JSONDecodeError:
                pass
    return state


def _binary(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _decryption_tables(state: dict):
    """The two published partial decryptions, as [question][cell] dicts."""
    master = None
    for key, value in state.items():
        if key.startswith("DECRYPTION_") and not key.startswith("DECRYPTION_FAIL"):
            master = json.loads(value) if isinstance(value, str) else value
            break
    commission = state.get("COMMISSION_DECRYPTION")
    if isinstance(commission, str):
        commission = json.loads(commission)
    return master, commission


# Expected data/encoding errors only: unexpected runtime failures must remain visible.
INPUT_ERRORS = (ValueError, TypeError, KeyError, IndexError, OverflowError)


def _ballot(tx, main_key, blind_key, dimension, result, dst, check_proofs,
            check_blind_signatures, check_structure=True):
    """§4.5.3: BS authorization, shape, sum linkage, then every OR proof.

    Only return ciphertexts after all enabled checks pass. Sum linkage and
    membership are distinct: neither may substitute for the other. See the
    module checklist and tests/test_crypto.py::test_range_proof_and_linkage.
    """
    if check_blind_signatures:
        try:
            signature = _binary(tx.param("blindSig"))
            if not tezhu.verify(blind_key, tx.sender.encode(), signature, dst=dst):
                result.bad_blind_signature.append(tx.tx_id)
                return None
        except INPUT_ERRORS as error:
            result.bad_blind_signature.append(tx.tx_id)
            result.notes.append(f"blind signature {tx.tx_id}: {error}")
            return None
    try:
        questions = bulletin.decode_bulletin(_binary(tx.param("vote")))
        if len(questions) != len(dimension):
            raise ValueError("question count does not match dimension")
        per_question = []
        for question, (low, high, options) in zip(questions, dimension):
            if len(question.options) != options:
                raise ValueError("option count does not match dimension")
            cells = [(curve.decompress(option.A), curve.decompress(option.B))
                     for option in question.options]
            if check_structure:
                # Independent valid proofs are insufficient: bind the sum to these options.
                if question.sum is None:
                    raise ValueError("option count / sum cell does not match dimension")
                if (curve.add_many(cell[0] for cell in cells) != curve.decompress(question.sum.A)
                        or curve.add_many(cell[1] for cell in cells) != curve.decompress(question.sum.B)):
                    result.bad_zkp.append(tx.tx_id)
                    return None
            if check_proofs:
                started = time.perf_counter()
                try:
                    proofs = [(list(range(low, high + 1)), question.sum)] + [
                        ([0, 1], option) for option in question.options]
                    proof_ok = True
                    for messages, proof in proofs:
                        result.ballot_zkp_checks += 1
                        if not zkp.verify_range_proof(main_key, messages, vars(proof)):
                            proof_ok = False
                            break
                    if not proof_ok:
                        result.bad_zkp.append(tx.tx_id)
                        return None
                except INPUT_ERRORS as error:
                    result.bad_zkp.append(tx.tx_id)
                    result.notes.append(f"range proof {tx.tx_id}: {error}")
                    return None
                finally:
                    result.ballot_zkp_seconds += time.perf_counter() - started
            per_question.append(cells)
        return per_question
    except INPUT_ERRORS as error:
        result.bad_shape.append(tx.tx_id)
        result.notes.append(f"bulletin {tx.tx_id}: {error}")
        return None


def audit(path: Path, *, verify_tx_signatures: bool = True, dst: bytes = DST_BLIND_ROP,
          max_votes: int | None = None, check_proofs: bool = True,
          check_blind_signatures: bool = True, check_structure: bool = True) -> AuditResult:
    if max_votes is not None and (type(max_votes) is not int or max_votes <= 0):
        raise ValueError("max_votes must be a positive integer")
    path = Path(path)
    result = AuditResult(contract=contract_id(path), enabled_checks={
        "tx_signatures": verify_tx_signatures, "range_proofs": check_proofs,
        "blind_signatures": check_blind_signatures, "ballot_structure": check_structure})
    try:
        _audit(path, result, verify_tx_signatures, dst, max_votes, check_proofs,
               check_blind_signatures, check_structure)
    except INPUT_ERRORS + (OSError, zipfile.BadZipFile) as error:
        result.error = f"invalid export/state in {path.name}: {error}"
    return result


def _audit(path, result, verify_tx_signatures, dst, max_votes, check_proofs,
           check_blind_signatures, check_structure):
    transactions = load_export(path)
    result.transactions = len(transactions)
    state = contract_state(transactions)
    voting_base = state.get("VOTING_BASE") or {}
    if not isinstance(voting_base, dict):
        raise ValueError("malformed VOTING_BASE")
    dimension = voting_base.get("dimension") or []
    blind_params = voting_base.get("blindSigParams") or []
    if not (state.get("MAIN_KEY") and blind_params and dimension):
        result.notes.append("incomplete contract state (MAIN_KEY / VOTING_BASE / dimension)")
        return
    if not isinstance(dimension, list) or any(
            not isinstance(row, list) or len(row) != 3 or
            any(type(n) is not int for n in row) or not 0 <= row[0] <= row[1] <= row[2]
            or row[2] <= 0 for row in dimension):
        raise ValueError("invalid dimension")
    main_key = curve.decompress(bytes.fromhex(state["MAIN_KEY"]))
    blind_key = bytes.fromhex(str(blind_params[0]).rjust(260, "0"))
    result.issued = sum(1 for tx in transactions if tx.operation == "blindSigIssue")
    votes = [tx for tx in transactions if tx.accepted_vote()]
    result.accepted = len(votes)
    result.rejected = sum(tx.operation == "vote" and not tx.accepted_vote() for tx in transactions)
    for tx in transactions:
        try:
            if int(tx.fee) != 0:
                raise ValueError("nonzero transaction fee is unsupported")
            if not verify_tx_signatures:
                continue
            inner = {"type": tx.type, "version": tx.version, "ts": tx.ts,
                     "senderPublicKey": tx.sender, "params": tx.params,
                     "extra": tx.extra, "fee": tx.fee, "feeAssetId": tx.fee_asset_id,
                     "contractId": result.contract}
            message = bulletin.transaction_bytes(inner)
            public_key = curve.from_le_xy(bulletin.b58decode(tx.sender))
            signature = bulletin.b58decode(tx.signature)
            if not gost3410.verify(public_key, message, signature):
                result.wrong_tx_signature.append(tx.tx_id)
        except INPUT_ERRORS as error:
            result.wrong_tx_signature.append(tx.tx_id)
            result.notes.append(f"transaction {tx.tx_id}: {error}")

    seen = set()
    bulletins = []
    result.sampled = max_votes is not None and len(votes) > max_votes
    for index, tx in enumerate(votes):
        duplicate = tx.sender in seen
        seen.add(tx.sender)
        if duplicate:
            result.revotes.append(tx.tx_id)
        if max_votes is not None and index >= max_votes:
            continue
        result.checked_ballots += 1
        if duplicate:
            continue
        ballot = _ballot(tx, main_key, blind_key, dimension, result, dst, check_proofs,
                         check_blind_signatures, check_structure)
        if ballot is not None:
            bulletins.append(ballot)
    result.valid_bulletins = len(bulletins)
    if state.get("DKG_KEY") and state.get("COMMISSION_KEY"):
        pk1 = curve.decompress(bytes.fromhex(state["DKG_KEY"]))
        pk2 = curve.decompress(bytes.fromhex(state["COMMISSION_KEY"]))
        result.key_aggregation_ok = elgamal.key_agg(pk1, pk2) == main_key
    else:
        result.notes.append("partial public keys are missing")
        return

    published = state.get("RESULTS")
    if published is not None:
        if (not isinstance(published, list) or len(published) != len(dimension) or
                any(not isinstance(row, list) or len(row) != dim[2] or
                    any(type(n) is not int or n < 0 for n in row)
                    for row, dim in zip(published, dimension))):
            raise ValueError("malformed published RESULTS")
        result.published = published
    else:
        result.notes.append("published RESULTS are missing")
    if result.sampled or len(bulletins) != len(votes):
        result.notes.append("full-election decryption/tally not checked against a partial ballot sum")
        return
    if not bulletins:
        result.tally = [[0] * row[2] for row in dimension]
        result.results_match = result.tally == published if published is not None else None
        result.notes.append("empty election: decryption proofs for neutral ciphertexts unsupported")
        return
    result_started = time.perf_counter()
    summed = elgamal.add(bulletins)
    master, commission = _decryption_tables(state)
    if master is None or commission is None:
        result.notes.append("partial decryptions are not (yet) published")
        result.result_phase_seconds = time.perf_counter() - result_started
        return
    if not isinstance(voting_base.get("pollId"), str) or not voting_base["pollId"]:
        raise ValueError("missing or malformed pollId")
    for name, pk, table in (("Учетчик", pk1, master), ("Комиссия", pk2, commission)):
        if (not isinstance(table, list) or len(table) != len(dimension) or
                any(not isinstance(row, list) or len(row) != dim[2]
                    for row, dim in zip(table, dimension))):
            raise ValueError(f"malformed decryption table: {name}")
        valid = True
        for q, question in enumerate(summed):
            for c, cell in enumerate(question):
                result.result_decryption_checks += 1
                if not zkp.verify_decryption(pk, cell, table[q][c],
                                              poll_id=voting_base["pollId"]):
                    valid = False
                    break
            if not valid:
                break
        result.partial_decryption_ok[name] = valid

    h1, h2 = points_hash_mod_q([pk1, pk2]), points_hash_mod_q([pk2, pk1])
    targets = []
    for q, question in enumerate(summed):
        for c, (_, b_point) in enumerate(question):
            p1 = curve.decompress(bytes.fromhex(master[q][c]["P"]))
            p2 = curve.decompress(bytes.fromhex(commission[q][c]["P"]))
            targets.append(curve.sub(b_point, curve.mul_add(h1, p1, h2, p2)))
    solved = elgamal.solve_dlp_batch(targets, len(bulletins))
    tally, cursor = [], 0
    for question in summed:
        tally.append([solved[cursor + c] for c in range(len(question))])
        cursor += len(question)
    result.tally = tally
    result.results_match = tally == published if published is not None else None
    result.result_phase_seconds = time.perf_counter() - result_started


def audit_many(paths, **kwargs) -> list[AuditResult]:
    return [audit(Path(path), **kwargs) for path in paths]
