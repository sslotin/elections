"""Streaming verification of a raw DEG blockchain dump.

The raw dump interleaves transactions from many contracts, so a verifier has
to retain some state per election.  It does *not* need to retain the complete
transaction history: state writes, the set of voter keys, and one Jacobian
homomorphic accumulator per ciphertext cell are sufficient for this audit.

The equations, paper citations and acceptance/trust-boundary checklist are in
protocol.py's top comment and the primitive modules it references. This driver
must enforce the SAME checks and verdict as protocol.audit; tests run both on
the same public exports. Only accepted, unique ballots enter the accumulator;
workers return proof results, not trusted totals. Drain every outstanding
worker before checking the full sum. Never certify a partial/empty input or
count a failed election as both failed and incomplete. Raw JSON conversion
is transport parsing, NOT verification of block signatures or state execution.
"""

from __future__ import annotations

import collections
import gzip
import io
import json
import sys
import time
import zipfile
from concurrent.futures import Future, ProcessPoolExecutor
from multiprocessing import get_context
from pathlib import Path
from typing import Callable, Generator, Iterator

from tqdm import tqdm

from . import bulletin, curve, elgamal, gost3410, protocol, zkp
from .hashfn import DST_BLIND_ROP, points_hash_mod_q


# ---------------------------------------------------------------- raw dump --


def _official_entry(entry: dict) -> dict:
    """Convert a node data entry to the portal spelling in memory."""
    kind = entry["type"]
    value = entry["value"]
    output = {"key": entry["key"]}
    if kind == "string":
        output["stringValue"] = value
    elif kind == "integer":
        output["intValue"] = value
    elif kind == "boolean":
        output["boolValue"] = value
    elif kind == "binary":
        if not isinstance(value, str) or not value.startswith("base64:"):
            raise ValueError(f"binary entry without base64 prefix: {entry['key']}")
        output["binaryValue"] = value[len("base64:"):]
    else:
        raise ValueError(f"unknown data entry type {kind!r}")
    return output


def transaction_from_raw(outer: dict) -> protocol.Transaction | None:
    """Build the small in-memory transaction object used by ``protocol``."""
    if outer.get("type") != 105:
        return None
    inner = outer.get("tx")
    if not isinstance(inner, dict) or inner.get("type") not in (103, 104):
        return None

    inner_type = inner["type"]
    if inner_type == 103:
        contract_id = inner["id"]
        extra = {
            "image": inner.get("image") or "",
            "imageHash": inner.get("imageHash") or "",
            "contractName": inner.get("contractName") or "",
        }
    else:
        contract_id = inner["contractId"]
        extra = {"contractVersion": inner.get("contractVersion", 0)}

    proofs = inner.get("proofs") or []
    return protocol.Transaction(
        tx_id=inner["id"],
        type=inner_type,
        signature=proofs[0] if proofs else "",
        version=int(inner["version"]),
        ts=int(inner["timestamp"]),
        sender=inner["senderPublicKey"],
        fee=str(inner.get("fee", 0)),
        fee_asset_id=inner.get("feeAssetId") or "",
        params=[_official_entry(entry) for entry in inner.get("params") or []],
        diff=[_official_entry(entry) for entry in outer.get("results") or []],
        extra=extra,
        rollback="",
    )


ProgressCallback = Callable[[int], None]


def _is_jsonl_input(name: str) -> bool:
    """Recognize raw dump members, but not the collector's state metadata."""
    name = name.lower()
    return (Path(name).name != "state.json"
            and name.endswith((".json", ".jsonl", ".json.gz", ".jsonl.gz")))


def dump_size(path: Path) -> int | None:
    """Return the uncompressed JSONL size when it is cheaply knowable."""
    path = Path(path)
    if path.is_dir():
        members = [child for child in path.iterdir()
                   if child.is_file() and _is_jsonl_input(child.name)]
        if any(member.name.lower().endswith(".gz") for member in members):
            return None
        return sum(child.stat().st_size for child in members)
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            members = [info for info in archive.infolist()
                       if not info.is_dir() and _is_jsonl_input(info.filename)]
            if any(info.filename.lower().endswith(".gz") for info in members):
                return None
            return sum(info.file_size for info in members)
    if path.suffix.lower() == ".gz":
        # gzip does not expose the uncompressed size without reading it.
        return None
    return path.stat().st_size


def _stream_text(binary, progress: ProgressCallback | None = None,
                 offset: int = 0) -> Generator[str, None, int]:
    """Yield decoded lines and return the uncompressed member length."""
    with io.TextIOWrapper(binary, encoding="utf-8") as text:
        for line in text:
            if progress is not None:
                try:
                    progress(offset + binary.tell())
                except (AttributeError, OSError):
                    pass
            yield line
        return binary.tell()


def iter_dump_lines(path: Path, progress: ProgressCallback | None = None) -> Iterator[str]:
    """Stream JSONL chunks (including gzip chunks) in filename order."""
    path = Path(path)
    if path.is_dir():
        members = sorted(
            child for child in path.iterdir()
            if child.is_file() and _is_jsonl_input(child.name)
        )
        if not members:
            raise ValueError(f"no JSONL chunks found in {path}")
        offset = 0
        for member in members:
            if member.name.lower().endswith(".gz"):
                with gzip.open(member, "rb") as binary:
                    member_size = yield from _stream_text(binary, progress, offset)
            else:
                with member.open("rb") as binary:
                    member_size = yield from _stream_text(binary, progress, offset)
            offset += member_size
            if progress is not None:
                progress(offset)
        return

    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            members = sorted(
                (info for info in archive.infolist()
                 if not info.is_dir() and _is_jsonl_input(info.filename)),
                key=lambda info: info.filename,
            )
            if not members:
                raise ValueError(f"no JSONL member found in {path}")
            offset = 0
            for info in members:
                with archive.open(info, "r") as compressed:
                    if info.filename.lower().endswith(".gz"):
                        with gzip.GzipFile(fileobj=compressed, mode="rb") as binary:
                            member_size = yield from _stream_text(binary, progress, offset)
                    else:
                        member_size = yield from _stream_text(compressed, progress, offset)
                offset += member_size
                if progress is not None:
                    progress(offset)
        return

    if path.suffix.lower() == ".gz":
        with gzip.open(path, "rb") as binary:
            yield from _stream_text(binary, progress)
        return

    with path.open("rb") as binary:
        yield from _stream_text(binary, progress)


# -------------------------------------------------------------- ballot jobs --


def check_ballot(
    tx: protocol.Transaction,
    main_key: curve.Point,
    blind_key: bytes,
    dimension: list[list[int]],
    check_proofs: bool,
    check_ballot_checks: bool,
) -> tuple[list[list[elgamal.Ciphertext]] | None, protocol.AuditResult]:
    """Extract a ballot and optionally perform its independent checks."""
    local = protocol.AuditResult(enabled_checks={
        "tx_signatures": True,
        "range_proofs": check_proofs,
        "blind_signatures": check_ballot_checks,
        "ballot_structure": check_ballot_checks,
    })
    ballot = protocol._ballot(
        tx, main_key, blind_key, dimension, local, DST_BLIND_ROP,
        check_proofs, check_ballot_checks, check_ballot_checks,
    )
    return ballot, local


class BallotScheduler:
    """Bounded optional process pool for independent ballot checks.

    The default is deliberately synchronous. Processes also accelerate the
    Python fallback and parsing; each starts its own optional native EC backend
    when ``--workers`` is greater than one. At most two ballots per worker
    are in flight, so the raw dump is never accumulated in memory.
    """

    def __init__(self, workers: int) -> None:
        self.workers = workers
        # tqdm can start a monitor thread before the first submission. Forking
        # then risks inherited locks/native contexts; spawn is portable and clean.
        self.pool = (ProcessPoolExecutor(max_workers=workers, mp_context=get_context("spawn"))
                     if workers > 1 else None)
        self.queue: collections.deque[tuple["Election", Future]] = collections.deque()
        self.active = 0

    def submit(self, election: "Election", tx: protocol.Transaction,
               main_key: curve.Point, blind_key: bytes,
               dimension: list[list[int]], check_proofs: bool,
               check_ballot_checks: bool) -> None:
        if self.pool is None:
            election.apply_ballot(*check_ballot(
                tx, main_key, blind_key, dimension, check_proofs, check_ballot_checks
            ))
            return
        future = self.pool.submit(
            check_ballot, tx, main_key, blind_key, dimension,
            check_proofs, check_ballot_checks,
        )
        election.pending.append(future)
        self.queue.append((election, future))
        self.active += 1
        if self.active >= self.workers * 2:
            self.drain_one()

    def _complete(self, election: "Election", future: Future) -> None:
        self.active -= 1
        election.apply_ballot(*future.result())

    def drain_one(self) -> None:
        while self.queue:
            election, future = self.queue.popleft()
            if future not in election.pending:
                # It was drained explicitly while finalizing that election.
                continue
            election.pending.remove(future)
            self._complete(election, future)
            return

    def drain(self, election: "Election") -> None:
        while election.pending:
            future = election.pending.popleft()
            self._complete(election, future)

    def drain_all(self) -> None:
        while self.active:
            self.drain_one()

    def shutdown(self) -> None:
        if self.pool is not None:
            self.drain_all()
            self.pool.shutdown()


# --------------------------------------------------------------- elections --


class Election:
    """Minimal in-memory state needed to audit one contract."""

    def __init__(self, contract: str, check_proofs: bool,
                 check_ballot_checks: bool, verify_tx_signatures: bool, *,
                 results_only: bool = False,
                 excluded_ballots: dict[str, str] | None = None) -> None:
        self.result = protocol.AuditResult(
            contract=contract,
            enabled_checks={
                "tx_signatures": verify_tx_signatures,
                "range_proofs": check_proofs,
                "blind_signatures": check_ballot_checks,
                "ballot_structure": check_ballot_checks,
            },
        )
        self.check_proofs = check_proofs
        self.check_ballot_checks = check_ballot_checks
        self.verify_tx_signatures = verify_tx_signatures
        self.results_only = results_only
        self.excluded_ballots = excluded_ballots or {}
        self.results_seen = False
        self.state: dict = {}
        self.seen_voters: set[str] = set()
        self.pending_votes: list[protocol.Transaction] = []
        self.pending: collections.deque[Future] = collections.deque()
        self.accumulator: elgamal.CiphertextAccumulator | None = None
        self._configuration: tuple[curve.Point, bytes, list[list[int]]] | None = None
        self.finalized = False

    @staticmethod
    def _json_state(value, key: str):
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as error:
                raise ValueError(f"malformed {key}") from error
        return value

    def configuration(self) -> tuple[curve.Point, bytes, list[list[int]]] | None:
        """Return keys/dimension once the contract has started voting."""
        if self._configuration is not None:
            return self._configuration
        base = self._json_state(self.state.get("VOTING_BASE"), "VOTING_BASE")
        if not (self.state.get("MAIN_KEY") and isinstance(base, dict)
                and base.get("blindSigParams") and base.get("dimension")):
            return None
        dimension = base["dimension"]
        if (not isinstance(dimension, list) or any(
                not isinstance(row, list) or len(row) != 3 or
                any(type(number) is not int for number in row) or
                not 0 <= row[0] <= row[1] <= row[2] or row[2] <= 0
                for row in dimension)):
            raise ValueError("invalid dimension")
        main_key = curve.decompress(bytes.fromhex(str(self.state["MAIN_KEY"])))
        blind_key = bytes.fromhex(str(base["blindSigParams"][0]).rjust(260, "0"))
        self._configuration = (main_key, blind_key, dimension)
        return self._configuration

    def apply_state(self, tx: protocol.Transaction) -> None:
        """Replay the state semantics used by the batch verifier."""
        if tx.rollback == "-1" or tx.failed():
            return
        if tx.operation == "decryption":
            for entry in tx.diff:
                if entry["key"].startswith("DECRYPTION_"):
                    self.state[entry["key"]] = tx.param("decryption")
            return
        if tx.operation == "commissionDecryption":
            if any(entry["key"] == "COMMISSION_DECRYPTION" for entry in tx.diff):
                self.state["COMMISSION_DECRYPTION"] = tx.param("decryption")
            return
        if tx.operation not in protocol.STATE_OPERATIONS and tx.type != 103:
            return
        for entry in tx.diff:
            self.state[entry["key"]] = protocol._entry_value(entry)

    def ready_to_finalize(self) -> bool:
        """Wait for RESULTS and both decryption shares, which may follow it."""
        has_master = any(
            key.startswith("DECRYPTION_") and not key.startswith("DECRYPTION_FAIL")
            for key in self.state
        )
        return self.results_seen and has_master and "COMMISSION_DECRYPTION" in self.state

    def ballot_aggregate_complete(self) -> bool:
        """In results-only mode, allow only explicitly excluded ballots to be absent."""
        expected = self.result.accepted - len(self.result.excluded_ballots)
        return (self.result.valid_bulletins == expected and
                (self.results_only or expected == self.result.accepted))

    def _verify_transaction(self, tx: protocol.Transaction) -> None:
        try:
            if int(tx.fee) != 0:
                raise ValueError("nonzero transaction fee is unsupported")
            inner = {
                "type": tx.type,
                "version": tx.version,
                "ts": tx.ts,
                "senderPublicKey": tx.sender,
                "params": tx.params,
                "extra": tx.extra,
                "fee": tx.fee,
                "feeAssetId": tx.fee_asset_id,
                "contractId": self.result.contract,
            }
            message = bulletin.transaction_bytes(inner)
            public_key = curve.from_le_xy(bulletin.b58decode(tx.sender))
            signature = bulletin.b58decode(tx.signature)
            if not gost3410.verify(public_key, message, signature):
                self.result.wrong_tx_signature.append(tx.tx_id)
        except protocol.INPUT_ERRORS as error:
            self.result.wrong_tx_signature.append(tx.tx_id)
            self.result.notes.append(f"transaction {tx.tx_id}: {error}")

    def _submit_vote(self, tx: protocol.Transaction, scheduler: BallotScheduler) -> None:
        config = self.configuration()
        if config is None:
            self.pending_votes.append(tx)
            return
        scheduler.submit(
            self, tx, *config, self.check_proofs, self.check_ballot_checks
        )

    def flush_pending(self, scheduler: BallotScheduler) -> None:
        if not self.pending_votes:
            return
        if self.configuration() is None:
            return
        pending, self.pending_votes = self.pending_votes, []
        for tx in pending:
            self._submit_vote(tx, scheduler)

    def process(self, tx: protocol.Transaction, scheduler: BallotScheduler) -> None:
        self.result.transactions += 1
        if self.verify_tx_signatures:
            self._verify_transaction(tx)
        self.apply_state(tx)
        if tx.operation == "results" and "RESULTS" in self.state:
            self.results_seen = True
        try:
            self.flush_pending(scheduler)
        except protocol.INPUT_ERRORS as error:
            self.result.error = self.result.error or f"invalid contract state: {error}"

        if tx.operation == "blindSigIssue":
            self.result.issued += 1
        if tx.operation != "vote":
            return
        if not tx.accepted_vote():
            self.result.rejected += 1
            return

        self.result.accepted += 1
        self.result.checked_ballots += 1
        # Even in --results-only mode, deduplication determines which ciphertexts
        # belong to the election-wide sum; blind/signature/shape/ZKP checks are
        # disabled by check_ballot_checks instead.
        if tx.sender in self.seen_voters:
            self.result.revotes.append(tx.tx_id)
            return
        self.seen_voters.add(tx.sender)
        if self.results_only and tx.tx_id in self.excluded_ballots:
            self.result.excluded_ballots[tx.tx_id] = self.excluded_ballots[tx.tx_id]
            return
        try:
            self._submit_vote(tx, scheduler)
        except protocol.INPUT_ERRORS as error:
            self.result.error = self.result.error or f"invalid ballot {tx.tx_id}: {error}"

    def apply_ballot(self, ballot, local: protocol.AuditResult) -> None:
        """Merge a synchronous or worker result into this election."""
        if self.results_only:
            self.result.notes.extend(local.notes)
            if ballot is None:
                for tx_id in local.bad_shape + local.bad_zkp + local.bad_blind_signature:
                    reason = next((note for note in local.notes if tx_id in note),
                                  "could not decode ballot for aggregation")
                    self.result.excluded_ballots.setdefault(tx_id, reason)
        else:
            for name in ("bad_blind_signature", "bad_shape", "bad_zkp", "notes"):
                getattr(self.result, name).extend(getattr(local, name))
        self.result.ballot_zkp_seconds += local.ballot_zkp_seconds
        self.result.ballot_zkp_checks += local.ballot_zkp_checks
        if ballot is None:
            return
        if self.accumulator is None:
            self.accumulator = elgamal.CiphertextAccumulator(
                [len(question) for question in ballot]
            )
        started = time.perf_counter()
        self.accumulator.add(ballot)
        self.result.aggregation_seconds += time.perf_counter() - started
        self.result.aggregation_cells += sum(len(question) for question in ballot)
        self.result.valid_bulletins += 1

    def _published(self, dimension: list[list[int]]):
        published = self._json_state(self.state.get("RESULTS"), "RESULTS")
        if published is None:
            self.result.notes.append("published RESULTS are missing")
            return None
        if (not isinstance(published, list) or len(published) != len(dimension) or
                any(not isinstance(row, list) or len(row) != dim[2] or
                    any(type(number) is not int or number < 0 for number in row)
                    for row, dim in zip(published, dimension))):
            raise ValueError("malformed published RESULTS")
        self.result.published = published
        return published

    def finalize(self) -> protocol.AuditResult:
        if self.finalized:
            return self.result
        self.finalized = True
        try:
            config = self.configuration()
            if config is None:
                self.result.notes.append("incomplete contract state (MAIN_KEY / VOTING_BASE / dimension)")
                return self.result
            main_key, _blind_key, dimension = config
            self._normalise_json_state()
            # configuration() may have parsed VOTING_BASE before normalization;
            # use the normalized value for pollId and RESULTS below.
            base = self.state.get("VOTING_BASE")
            if not isinstance(base, dict):
                raise ValueError("malformed VOTING_BASE")

            if not self.ballot_aggregate_complete():
                self.result.notes.append(
                    "full-election decryption/tally not checked because included ballots "
                    "do not reconcile with accepted votes and explicit exclusions"
                )
                return self.result

            if not (self.state.get("DKG_KEY") and self.state.get("COMMISSION_KEY")):
                self.result.notes.append("partial public keys are missing")
                return self.result
            pk1 = curve.decompress(bytes.fromhex(self.state["DKG_KEY"]))
            pk2 = curve.decompress(bytes.fromhex(self.state["COMMISSION_KEY"]))
            self.result.key_aggregation_ok = elgamal.key_agg(pk1, pk2) == main_key
            published = self._published(dimension)

            if self.accumulator is None:
                self.result.tally = [[0] * row[2] for row in dimension]
                self.result.results_match = (
                    self.result.tally == published if published is not None else None
                )
                self.result.notes.append(
                    "empty election: decryption proofs for neutral ciphertexts unsupported"
                )
                return self.result

            if not isinstance(base.get("pollId"), str) or not base["pollId"]:
                raise ValueError("missing or malformed pollId")
            master, commission = protocol._decryption_tables(self.state)
            if master is None or commission is None:
                self.result.notes.append("partial decryptions are not (yet) published")
                return self.result

            started = time.perf_counter()
            try:
                summed = self.accumulator.finish()
                for name, pk, table in (("Учетчик", pk1, master), ("Комиссия", pk2, commission)):
                    if (not isinstance(table, list) or len(table) != len(dimension) or
                            any(not isinstance(row, list) or len(row) != dim[2]
                                for row, dim in zip(table, dimension))):
                        raise ValueError(f"malformed decryption table: {name}")
                    valid = True
                    for question_index, question in enumerate(summed):
                        for cell_index, cell in enumerate(question):
                            self.result.result_decryption_checks += 1
                            if not zkp.verify_decryption(
                                    pk, cell, table[question_index][cell_index],
                                    poll_id=base["pollId"]):
                                valid = False
                                break
                        if not valid:
                            break
                    self.result.partial_decryption_ok[name] = valid

                h1 = points_hash_mod_q([pk1, pk2])
                h2 = points_hash_mod_q([pk2, pk1])
                targets = []
                for question_index, question in enumerate(summed):
                    for cell_index, (_a_point, b_point) in enumerate(question):
                        p1 = curve.decompress(bytes.fromhex(master[question_index][cell_index]["P"]))
                        p2 = curve.decompress(bytes.fromhex(commission[question_index][cell_index]["P"]))
                        targets.append(curve.sub(b_point, curve.mul_add(h1, p1, h2, p2)))
                solved = elgamal.solve_dlp_batch(targets, self.result.valid_bulletins)
                tally, cursor = [], 0
                for question in summed:
                    tally.append([solved[cursor + cell] for cell in range(len(question))])
                    cursor += len(question)
                self.result.tally = tally
                self.result.results_match = (
                    tally == published if published is not None else None
                )
            finally:
                self.result.result_phase_seconds = time.perf_counter() - started
        except protocol.INPUT_ERRORS as error:
            self.result.error = f"invalid export/state: {error}"
        return self.result

    def _normalise_json_state(self) -> None:
        for key in protocol.JSON_STATE_KEYS:
            if key in self.state:
                self.state[key] = self._json_state(self.state[key], key)

    def release_heavy_state(self) -> None:
        """Free per-ballot memory after an election has been printed."""
        self.seen_voters.clear()
        self.pending_votes.clear()
        self.pending.clear()
        self.state.clear()
        self.accumulator = None
        self._configuration = None


# -------------------------------------------------------------- dump driver --


class StreamVerifier:
    def __init__(self, workers: int, results_only: bool,
                 excluded_ballots: dict[str, str] | None = None) -> None:
        self.scheduler = BallotScheduler(workers)
        self.results_only = results_only
        self.excluded_ballots = excluded_ballots or {}
        self.elections: dict[str, Election] = {}
        self.completed: list[protocol.AuditResult] = []
        self.blocks = 0
        self.contract_transactions = 0
        self.input_anomalies = 0
        self.progress = None

    def _write(self, message: str) -> None:
        if self.progress is None:
            print(message, flush=True)
        else:
            self.progress.write(message)

    def _election(self, contract: str) -> Election:
        election = self.elections.get(contract)
        if election is None:
            check_ballot_checks = not self.results_only
            election = self.elections[contract] = Election(
                contract, check_ballot_checks, check_ballot_checks,
                not self.results_only, results_only=self.results_only,
                excluded_ballots=self.excluded_ballots,
            )
        return election

    def _emit(self, result: protocol.AuditResult) -> None:
        if self.results_only and result.final_result_verified:
            status = (f"RESULTS VERIFIED (ballot checks skipped; "
                      f"excluded={len(result.excluded_ballots)})")
        elif result.verdict == "failed":
            status = "FAILED"
        elif result.verdict == "verified":
            status = "VERIFIED"
        else:
            status = "INCOMPLETE"
        if self.results_only:
            zkp_time = "skipped"
        else:
            per_ballot = result.ballot_zkp_seconds / max(result.valid_bulletins, 1)
            zkp_time = f"{per_ballot * 1000:.3f} ms/ballot"
        problems = (
            len(result.wrong_tx_signature), len(result.bad_blind_signature),
            len(result.bad_shape), len(result.bad_zkp), len(result.revotes),
        )
        ballot_counts = (
            f"accepted={result.accepted}; included_in_sum={result.valid_bulletins}; "
            f"excluded={len(result.excluded_ballots)}"
            if self.results_only else
            f"accepted={result.accepted}; valid_ballots={result.valid_bulletins}"
        )
        self._write(
            f"{result.contract}: {status}; transactions={result.transactions}; "
            f"{ballot_counts}; ballot_zkp={zkp_time}; "
            f"aggregation={result.aggregation_seconds:.3f}s; "
            f"final_result={result.result_phase_seconds:.3f}s; "
            f"results_match={result.results_match}; "
            f"problems(tx/blind/shape/zkp/revote)={problems}"
        )
        for tx_id, reason in sorted(result.excluded_ballots.items()):
            self._write(f"  excluded ballot: {tx_id}; reason={reason}")
        for note in result.notes:
            self._write(f"  note: {note}")
        self.completed.append(result)

    def finish_election(self, contract: str) -> None:
        election = self.elections.get(contract)
        if election is None or election.finalized:
            return
        self.scheduler.drain(election)
        election.flush_pending(self.scheduler)
        self.scheduler.drain(election)
        result = election.finalize()
        self._emit(result)
        election.release_heavy_state()

    def finish_all(self) -> None:
        self.scheduler.drain_all()
        for contract in sorted(self.elections):
            self.finish_election(contract)
        self.scheduler.shutdown()

    def run(self, path: Path) -> int:
        bar = None
        try:
            total = dump_size(path)
            bar = tqdm(
                total=total,
                desc="reading dump",
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                dynamic_ncols=True,
                mininterval=0.5,
                file=sys.stdout,
            )
            self.progress = bar
            last_position = 0

            def update_progress(position: int) -> None:
                nonlocal last_position
                if position < last_position:
                    return
                bar.update(position - last_position)
                last_position = position

            for line_number, line in enumerate(iter_dump_lines(path, update_progress), 1):
                if not line.strip():
                    continue
                self.blocks += 1
                try:
                    block = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"invalid JSON at input line {line_number}") from error
                for outer in block.get("transactions") or []:
                    tx = transaction_from_raw(outer)
                    if tx is None:
                        continue
                    contract = (
                        tx.tx_id if tx.type == 103 else outer["tx"]["contractId"]
                    )
                    election = self._election(contract)
                    self.contract_transactions += 1
                    if election.finalized:
                        self.input_anomalies += 1
                        self._write(
                            f"input anomaly: transaction {tx.tx_id} for {contract} "
                            "appeared after results/decryption finalization"
                        )
                        continue
                    if (election.results_seen and
                            tx.operation not in {"decryption", "commissionDecryption"}):
                        self.input_anomalies += 1
                        self._write(
                            f"input anomaly: transaction {tx.tx_id} for {contract} "
                            f"({tx.operation}) appeared after RESULTS"
                        )
                        continue
                    if tx.operation == "vote":
                        bar.set_description(
                            "checking ballot (ZKP)" if not self.results_only
                            else "aggregating ciphertexts",
                            refresh=False,
                        )
                    elif tx.operation == "results":
                        bar.set_description("checking final result", refresh=False)
                    else:
                        bar.set_description(
                            "checking transaction" if not self.results_only
                            else "replaying state",
                            refresh=False,
                        )
                    election.process(tx, self.scheduler)
                    # Decryption shares can follow RESULTS in the dump. Finalize
                    # only once the result and both shares have been replayed.
                    if election.ready_to_finalize():
                        self.finish_election(contract)
                    bar.set_description("reading dump", refresh=False)
                if self.blocks % 5000 == 0:
                    self._write(
                        f"read blocks={self.blocks:,}; contract_transactions="
                        f"{self.contract_transactions:,}; elections={len(self.elections):,}"
                    )
            bar.set_description("finalizing")
            self.finish_all()
        except protocol.INPUT_ERRORS + (OSError, zipfile.BadZipFile) as error:
            self.scheduler.shutdown()
            self._write(f"input error: {error}")
            return 1
        finally:
            if bar is not None:
                bar.close()
            self.progress = None

        failed = sum(result.verdict == "failed" for result in self.completed)
        incomplete = sum(
            result.verdict != "failed" and (
                result.verdict != "verified" if not self.results_only
                else not result.final_result_verified)
            for result in self.completed
        )
        verified = len(self.completed) - failed - incomplete
        excluded = sum(len(result.excluded_ballots) for result in self.completed)
        self._write(
            f"finished: elections={len(self.completed):,}; verified={verified:,}; "
            f"failed={failed:,}; incomplete={incomplete:,}; "
            f"excluded_ballots={excluded:,}; input_anomalies={self.input_anomalies:,}"
        )
        if not self.completed:
            self._write("incomplete: no elections found")
        return 1 if failed or self.input_anomalies else (2 if incomplete or not self.completed else 0)


def verify(path: Path, *, workers: int = 1, results_only: bool = False,
           excluded_ballots: dict[str, str] | None = None) -> int:
    if workers < 1:
        raise ValueError("workers must be positive")
    if excluded_ballots and not results_only:
        raise ValueError("ballot exclusions are only supported with results_only=True")
    return StreamVerifier(workers, results_only, excluded_ballots).run(Path(path))
