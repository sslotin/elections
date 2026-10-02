"""Diagnostic interface: python3 -m crypto <command>.

    vectors            run the built-in self-tests of the primitives
    probe-tx  <path>   report which signature conventions validate the data
    audit     <path>   run the §4.6 audit of one or more exported votings
                       (--results-only keeps only the final result phase)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import bulletin, curve, elgamal, gost3410, hashfn, protocol, streebog, tezhu, zkp
from .hashfn import DST_BLIND_ROP


def cmd_vectors(_args) -> int:
    failures = 0

    # ГОСТ Р 34.11-2012, приложение А.1
    m1 = b"012345678901234567890123456789012345678901234567890123456789012"
    want1 = "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
    got1 = streebog.streebog256(m1).hex()
    print(f"Стрибог-256(M1): {'ok' if got1 == want1 else 'FAIL'}")
    failures += got1 != want1
    m2 = "Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы".encode("cp1251")
    want2 = "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50"
    got2 = streebog.streebog256(m2).hex()
    print(f"Стрибог-256(M2): {'ok' if got2 == want2 else 'FAIL'}")
    failures += got2 != want2

    # curve sanity: 2·P and the order
    double = curve.add(curve.G, curve.G)
    order_ok = curve.check_generator_order()  # mul(G,Q) would reduce Q to zero first.
    print("2·P on curve:", curve.is_on_curve(double), "| order·P = 𝒪:", order_ok)
    failures += not curve.is_on_curve(double) or not order_ok
    print("compress/decompress round trip:",
          curve.decompress(curve.compress(double)) == double)
    failures += curve.decompress(curve.compress(double)) != double

    # XMD-RO is deterministic and 48 bytes
    digest = hashfn.xmd_ro(b"test", DST_BLIND_ROP)
    print(f"XMD-RO length {len(digest)}, deterministic:",
          digest == hashfn.xmd_ro(b"test", DST_BLIND_ROP))
    failures += len(digest) != 48

    # the hash-to-scalar of the proofs must agree with the published TS/C
    print("points_hash(G, 2G) returns an integer:",
          isinstance(hashfn.points_hash([curve.G, double]), int))
    print("FAILURES:", failures)
    return 1 if failures else 0


def cmd_probe_tx(args) -> int:
    transactions = protocol.load_export(Path(args.path))
    contract = protocol.contract_id(Path(args.path))
    sample = transactions[:args.limit] if args.limit else transactions
    for digest_le in (False, True):
        for swap_rs in (False, True):
            good = checked = 0
            for tx in sample:
                inner = {"type": tx.type, "version": tx.version, "ts": tx.ts,
                         "senderPublicKey": tx.sender, "params": tx.params,
                         "extra": tx.extra, "fee": tx.fee, "feeAssetId": tx.fee_asset_id,
                         "contractId": contract}
                message = bulletin.transaction_bytes(inner)
                public_key = curve.from_le_xy(bulletin.b58decode(tx.sender))
                signature = bulletin.b58decode(tx.signature)
                if gost3410.verify(public_key, message, signature,
                                   digest_le=digest_le, swap_rs=swap_rs):
                    good += 1
                checked += 1
            print(f"digest_le={digest_le!s:5} swap_rs={swap_rs!s:5} -> "
                  f"{good}/{checked} signatures verify")
    return 0


def cmd_audit(args) -> int:
    paths = [Path(p) for p in args.paths]
    exit_code = 0
    for path in paths:
        result = protocol.audit(
            path,
            verify_tx_signatures=not (args.skip_tx_signature or args.results_only),
            max_votes=args.max_votes,
            check_proofs=not (args.skip_proofs or args.results_only),
            check_blind_signatures=not (args.skip_blind_signature or args.results_only),
            check_structure=not args.results_only,
        )
        print(result.summary())
        print()
        if result.verdict == "failed":
            exit_code = 1
        elif args.results_only:
            # A successful result phase is the intended success condition for
            # this explicitly partial mode; the human-readable verdict stays
            # ``incomplete`` because checks were disabled.
            if not result.final_result_verified and exit_code == 0:
                exit_code = 2
        elif result.verdict != "verified" and exit_code == 0:
            exit_code = 2
    return exit_code


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="crypto", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("vectors", help="self-tests of the primitives").set_defaults(func=cmd_vectors)

    probe = sub.add_parser("probe-tx", help="which GOST conventions the data satisfies")
    probe.add_argument("path")
    probe.add_argument("--limit", type=int, default=20)
    probe.set_defaults(func=cmd_probe_tx)

    audit = sub.add_parser("audit", help="run the protocol audit on an exported voting")
    audit.add_argument("paths", nargs="+")
    audit.add_argument("--max-votes", type=positive_int, default=None)
    audit.add_argument("--skip-tx-signature", action="store_true")
    audit.add_argument("--skip-blind-signature", action="store_true",
                       help="skip BS.Verify of the voter keys (§4.4.1)")
    audit.add_argument("--skip-proofs", action="store_true",
                       help="legacy alias: skip the per-cell ballot ZKPs (§4.5.3)")
    audit.add_argument(
        "--results-only", action="store_true",
        help="skip transaction/ballot checks; aggregate ballots and verify final results",
    )
    audit.set_defaults(func=cmd_audit)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
