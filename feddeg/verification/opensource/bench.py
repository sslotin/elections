#!/usr/bin/env python3
"""Benchmark the verifier's hot checks on one tiny seed voting.

The seed is repeated in the timing loops; the full EDG 2025 counts are used
only to project CPU hours and draw ``pie-chart.png``. No large dump is read.
"""

from __future__ import annotations

import argparse
import base64
import json
import platform
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True

from crypto import bulletin, curve, elgamal, gost3410, protocol, tezhu, zkp
from crypto.hashfn import DST_BLIND_ROP


# Measured corpus distribution from EDG 2025. These are counts, not timings.
CORPUS = {
    "transactions": 5_842_689,
    "votes": 2_881_290,
    "option_proof_cells": 19_475_976 - 2_881_290,
    "sum_proof_cells": 2_881_290,
    "option_contributions": 19_475_976 - 2_881_290,
    "elections": 3_046,
    "decryption_cells": 15_299,
    # The DLP model uses one shared generator walk per election and is
    # approximated by one walk of the average election's vote count.
    "dlp_steps": 2_881_290,
}

SERIES = (
    ("range", "Доказательства\nдиапазона"),
    ("tx", "ГОСТ-подписи\nтранзакций"),
    ("blind", "Слепые подписи\nTeZhu"),
    ("add", "Агрегация\nшифротекстов"),
    ("decryption", "Доказательства\nрасшифровки"),
    ("dlp", "Восстановление итогов"),
    ("key_agg", "Агрегация ключей"),
)


def default_fixture() -> Path:
    """Locate the small immutable fixture in the surrounding verification tree."""
    candidates = (
        Path(__file__).resolve().parents[3]
        / "data/verification-fixtures/4BbdvzVdbyQES6ARbt4YDB4htfUYgwUVGpQYNa6dLj3u.zip",
        Path(__file__).resolve().parents[4]
        / "verification/tests/fixtures/4BbdvzVdbyQES6ARbt4YDB4htfUYgwUVGpQYNa6dLj3u.zip",
        Path(__file__).resolve().parents[1]
        / "tests/fixtures/4BbdvzVdbyQES6ARbt4YDB4htfUYgwUVGpQYNa6dLj3u.zip",
    )
    for path in candidates:
        if path.is_file():
            return path
    raise FileNotFoundError(
        "small benchmark fixture not found; pass it explicitly with --fixture PATH"
    )


def timed(function, repeats: int) -> float:
    started = time.perf_counter()
    for _ in range(repeats):
        if function() is False:
            raise ValueError("benchmark check failed; refusing to time invalid proofs")
    return (time.perf_counter() - started) / repeats


def transaction_message(tx: protocol.Transaction, contract: str) -> bytes:
    return bulletin.transaction_bytes({
        "type": tx.type,
        "version": tx.version,
        "ts": tx.ts,
        "senderPublicKey": tx.sender,
        "params": tx.params,
        "extra": tx.extra,
        "fee": tx.fee,
        "feeAssetId": tx.fee_asset_id,
        "contractId": contract,
    })


def load_seed(path: Path) -> dict:
    transactions = protocol.load_export(path)
    state = protocol.contract_state(transactions)
    base = state["VOTING_BASE"]
    contract = protocol.contract_id(path)
    vote = next(tx for tx in transactions if tx.operation == "vote" and tx.accepted_vote())
    questions = bulletin.decode_bulletin(base64.b64decode(vote.param("vote")))
    question = questions[0]
    dimension = base["dimension"]
    main_key = curve.decompress(bytes.fromhex(state["MAIN_KEY"]))
    blind_key = bytes.fromhex(str(base["blindSigParams"][0]).rjust(260, "0"))

    local = protocol.AuditResult()
    ballot = protocol._ballot(
        vote, main_key, blind_key, dimension, local, DST_BLIND_ROP,
        False, False, False,
    )
    accumulator = elgamal.CiphertextAccumulator([len(q) for q in ballot])
    # Final decryption proofs bind the WHOLE election, even with --fixture pointing
    # at an export larger than the one-vote default. Timing a failed proof lies.
    for accepted in (tx for tx in transactions if tx.accepted_vote()):
        cells = protocol._ballot(accepted, main_key, blind_key, dimension,
                                 protocol.AuditResult(), DST_BLIND_ROP, False, False, False)
        if cells is None:
            raise ValueError("benchmark fixture contains a malformed ballot")
        accumulator.add(cells)
    summed = accumulator.finish()
    master, commission = protocol._decryption_tables(state)
    pk1 = curve.decompress(bytes.fromhex(state["DKG_KEY"]))
    pk2 = curve.decompress(bytes.fromhex(state["COMMISSION_KEY"]))

    return {
        "contract": contract,
        "tx": next(tx for tx in transactions if tx.type == 104),
        "vote": vote,
        "main_key": main_key,
        "blind_key": blind_key,
        "dimension": dimension,
        "question": question,
        "ballot": ballot,
        "summed_cell": summed[0][0],
        "master_cell": master[0][0],
        "commission_cell": commission[0][0],
        "pk1": pk1,
        "pk2": pk2,
        "poll_id": base["pollId"],
    }


def benchmark(seed: dict, repeats: int) -> dict[str, float]:
    tx = seed["tx"]
    vote = seed["vote"]
    question = seed["question"]
    option = question.options[0]
    total = question.sum
    dimension = seed["dimension"][0]
    tx_message = transaction_message(tx, seed["contract"])
    tx_public_key = curve.from_le_xy(bulletin.b58decode(tx.sender))
    tx_signature = bulletin.b58decode(tx.signature)
    blind_signature = base64.b64decode(vote.param("blindSig"))

    option_proof = {
        "A": option.A, "B": option.B, "As": option.As,
        "Bs": option.Bs, "c": option.c, "r": option.r,
    }
    sum_proof = {
        "A": total.A, "B": total.B, "As": total.As,
        "Bs": total.Bs, "c": total.c, "r": total.r,
    }
    option_count = sum(len(q) for q in seed["ballot"])
    aggregate = elgamal.CiphertextAccumulator([len(q) for q in seed["ballot"]])

    measurements = {
        "tx": timed(
            lambda: gost3410.verify(tx_public_key, tx_message, tx_signature),
            repeats,
        ),
        "blind": timed(
            lambda: tezhu.verify(
                seed["blind_key"], vote.sender.encode(), blind_signature,
                dst=DST_BLIND_ROP,
            ),
            repeats,
        ),
        "option_proof": timed(
            lambda: zkp.verify_range_proof(
                seed["main_key"], [0, 1], option_proof,
            ),
            repeats,
        ),
        "sum_proof": timed(
            lambda: zkp.verify_range_proof(
                seed["main_key"], list(range(dimension[0], dimension[1] + 1)), sum_proof,
            ),
            repeats,
        ),
        "add_per_option": timed(lambda: aggregate.add(seed["ballot"]), repeats) / option_count,
        "decryption": timed(
            lambda: zkp.verify_decryption(
                seed["pk1"], seed["summed_cell"], seed["master_cell"],
                poll_id=seed["poll_id"],
            ),
            repeats,
        ),
        "dlp_step": timed(
            lambda: elgamal.solve_dlp_batch([curve.mul_generator(1000)], 1000),
            max(1, repeats // 4),
        ) / 1000,
        "key_agg": timed(
            lambda: elgamal.key_agg(seed["pk1"], seed["pk2"]),
            repeats,
        ),
    }
    # Keep raw seconds as well as the legacy corpus projection (CPU hours).
    per_check = {f"{key}_seconds": value for key, value in measurements.items()}
    measurements["range"] = (
        measurements["option_proof"] * CORPUS["option_proof_cells"]
        + measurements["sum_proof"] * CORPUS["sum_proof_cells"]
    ) / 3600
    measurements["tx"] = measurements["tx"] * CORPUS["transactions"] / 3600
    measurements["blind"] = measurements["blind"] * CORPUS["votes"] / 3600
    measurements["add"] = (
        measurements["add_per_option"] * CORPUS["option_contributions"] / 3600
    )
    measurements["decryption"] = (
        measurements["decryption"] * 2 * CORPUS["decryption_cells"] / 3600
    )
    measurements["dlp"] = measurements["dlp_step"] * CORPUS["dlp_steps"] / 3600
    measurements["key_agg"] = measurements["key_agg"] * CORPUS["elections"] / 3600
    measurements.update(per_check)
    return measurements


def make_chart(costs: dict[str, float], output: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = [label for key, label in SERIES]
    values = [costs[key] for key, _ in SERIES]
    total = sum(values)
    colors = ["#d95f02", "#1b9e77", "#7570b3", "#66a61e", "#e7298a", "#a6761d", "#666666"]

    fig, ax = plt.subplots(figsize=(8, 6), constrained_layout=True)
    wedges, _, _ = ax.pie(
        values,
        colors=colors,
        startangle=90,
        counterclock=False,
        autopct=lambda percent: f"{percent:.1f}%" if percent >= 0.1 else "",
        pctdistance=0.72,
        textprops={"fontsize": 9},
    )
    ax.legend(
        wedges,
        [f"{label.replace(chr(10), ' ')} — {value:.3g} ч" for label, value in zip(labels, values)],
        title=f"Итого: {total:.3g} CPU-ч",
        loc="center left",
        bbox_to_anchor=(0.98, 0.5),
        fontsize=9,
    )
    ax.set_title("Оценка времени полной проверки ЕДГ-2025\n(замер на малой контрольной выгрузке)")
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=160, bbox_inches="tight")
    plt.close(fig)

    print(f"saved {output}; projected total={total:.3g} CPU-h")
    for key, label in SERIES:
        print(f"{label.replace(chr(10), ' ')}: {costs[key] / total:.3%}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=None,
                        help="small exported voting used as the cryptographic seed")
    parser.add_argument("--repeats", type=int, default=10,
                        help="timing repetitions per primitive (default: 10)")
    parser.add_argument(
        "--output", type=Path,
        default=Path(__file__).with_name("pie-chart.png"),
        help="output PNG (default: pie-chart.png next to this script)",
    )
    parser.add_argument("--no-plot", action="store_true", help="do not import matplotlib or write a chart")
    parser.add_argument("--json", type=Path, help="write timings and backend metadata to this path")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    fixture = args.fixture or default_fixture()
    seed = load_seed(fixture)
    costs = benchmark(seed, args.repeats)
    print(f"seed={fixture}; backend={curve.BACKEND}; repeats={args.repeats}")
    print(f"option proof: {costs['option_proof_seconds'] * 1000:.3f} ms; "
          f"sum proof: {costs['sum_proof_seconds'] * 1000:.3f} ms")
    print("measured/projected CPU hours:")
    for key, _ in SERIES:
        print(f"  {key:12} {costs[key]:.6g}")
    if args.json:
        args.json.write_text(json.dumps({
            "backend": curve.BACKEND, "python": platform.python_version(),
            "platform": platform.platform(), "fixture": str(fixture),
            "repeats": args.repeats, "measurements": costs,
        }, indent=2) + "\n", encoding="utf-8")
    if not args.no_plot:
        make_chart(costs, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
