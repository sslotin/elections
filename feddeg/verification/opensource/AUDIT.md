# Review map for the export verifier

This is an implementation-review guide, not a security certification. Start with
`crypto/protocol.py`'s top comment for the end-to-end checklist; each primitive's
top comment gives its sources, notation, exact transcript, equations, input
validation, and limits. Paths to the protocol PDF are relative to this directory.

## Reproduce before judging

From this directory, with Python >=3.10, libgcrypt and tqdm:

```sh
python3 -B -m unittest discover -s tests -v
python3 -B -m crypto vectors
python3 -B bench.py --no-plot --repeats 100 --json /tmp/feddeg-bench.json
```

Repeat tests and benchmarks with `FEDDEG_EC_BACKEND=python` and
`FEDDEG_EC_BACKEND=openssl`. `auto` (default) falls back only if the optional
OpenSSL library/API is unavailable; `openssl` fails explicitly in that case.
Set the environment variable before Python starts, including for spawned workers.
No native handles or trusted verdicts are passed between workers. All EC inputs
are public: neither backend promises constant-time secret-key operations.

Test data and its provenance/hashes live in `../../../data/verification-fixtures/`.
The two actual exports contain 26 transactions and 5 accepted ballots in total.
They pin production byte conventions; they do not establish export authenticity.
Tests also check affine-vs-optimized arithmetic, explicit XMD block construction,
known Streebog answers, the public decryption challenge trace, proof mutations,
independent ballot sum linkage, disabled-check verdicts, raw-dump/batch parity,
multiple processes, missing data, bounded discrete logs and malformed encodings.

Do not treat a self-generated proof alone as an independent oracle: prover and
verifier can share the same bug. Check equations in their direct form with the
slow affine operations, compare with published algorithms and known answers,
and mutate statements/commitments/responses independently. The native backend
is a second arithmetic implementation, not a second protocol implementation.

## Sources by obligation

| Obligation | First code to inspect | Primary reference |
|---|---|---|
| Curve, subgroup, canonical points | `curve.py`, `_openssl.py` | RFC 9215 Appendix C; RFC 4357 §11.4; SEC 1 v2 §§2.3, 3.2.2; EFD Jacobian formulas |
| Streebog digest | `streebog.py` | RFC 6986, especially the 256-bit examples |
| Domain separation / hash-to-scalar | `hashfn.py` | PDF §2.1 raster formula; RFC 9380 §§5.2–5.3.1 |
| Transaction authorization | `gost3410.py`, `bulletin.py` | RFC 7091 §6.2; chain serializer separately |
| Blind authorization | `tezhu.py` | Tessaro–Zhu, EUROCRYPT 2022, BS3.Ver, ePrint 2022/047 §5.1, Fig. 7 |
| Option/sum membership | `zkp.py` | Chaum–Pedersen, CRYPTO '92; Cramer–Damgård–Schoenmakers, EUROCRYPT '94; Fiat–Shamir, CRYPTO '86 |
| Shape, linked sum, unique voter key | `protocol._ballot`, audit drivers | PDF §§4.4–4.6; these are separate protocol invariants, not extra proof schemes |
| Weighted key and ciphertext aggregation | `elgamal.py` | ElGamal 1985; Cramer–Gennaro–Schoenmakers 1997; PDF §2.4 and production source |
| Two authenticated partial decryptions | `zkp.verify_decryption` | Chaum–Pedersen; PDF §2.4 Dverify |
| Bounded tally and complete coverage | `elgamal.solve_dlp_batch`, both drivers | Algebra in `elgamal.py`; PDF §§4.5–4.7 |

Full titles, stable URLs and equation-to-code explanations are beside the checks,
not just in this table. Public implementation comparisons use
`cikrf/deg2025` revision `d1fc451622342990e436afdc5849e6e9969f62c7`.

## Do not conflate the PDF and deployed profile

The PDF contains rasterized algorithms. Read the images under
`../../protocol/protocol2023-assets/`; extracting text alone hides them.

* `05-encryption-keyagg.png` and `15-decryption-aggregate.png` assign
  `h1=H(Q2||Q1)` to Q1 and `h2=H(Q1||Q2)` to Q2. Production assigns them in the
  opposite order. Real MAIN_KEY and partial-decryption/tally checks match the
  production order, not a silent translation of the PDF's formula.
* `09-encryption-rverify.png` hashes `G||PK||A||B||As...||Bs...` with the PDF's
  general binary point representation. Production omits G and hashes lowercase
  ASCII hex of compressed points. The verifier intentionally matches production.
* Range-proof scalars and decryption responses are BE32 on the wire; TeZhu
  scalars are LE32. Transaction signatures are `s_BE32||r_BE32`, with digest
  bytes interpreted LE. One blanket "everything is little-endian" rule is wrong.
* The PDF incorrectly labels the partial-knowledge paper CRYPTO '94 rather than
  EUROCRYPT '94, and cites [9] for TeZhu although its bibliography puts it at [10].
* Zero range-proof challenges/responses and zero TeZhu challenges are rejected
  as required by the PDF; a decryption response of zero is permitted. The
  production C verifier is not a normative oracle for all rejection behavior.

Compatibility on these samples cannot resolve specification ambiguity. There is
no proof here that every difference is harmless, or that the deployment meets
the papers' security assumptions. Do not "fix" a transcript or swap coefficients
without treating that as a protocol/profile change and retesting real exports.

## Scope of a passing verdict

`verified` requires all enabled checks, full ballot coverage, both authorities'
proofs, key aggregation and exact tally equality. Disabling sum linkage/shape
must downgrade the verdict just like disabling signatures or range proofs.
`--results-only` deliberately certifies less. No-election input and unsupported
neutral-ciphertext/empty-election proofs cannot become full success.

A valid request signature does **not** authenticate the export's state diffs,
VOTE/FAIL markers or completeness. The drivers trust accepted-state replay and
an immutable configuration once voting starts. Separate work is needed for:

* authenticated chain history, block signatures/consensus, deterministic
  smart-contract execution, finality and export completeness;
* authorized authority keys, voter rolls, one blind issuance per eligible person;
* DKG, secret sharing, commitments, honest randomness and key custody;
* the interactive blind-signing protocol, deployment privacy, coercion resistance,
  availability and end-user verification.

These are limits of the audit, not conclusions that those components are broken.

## Performance evidence and limitations

The initial one-vote seed benchmark on this host measured about 8.02 ms per
binary range proof and 4.13 ms per singleton sum proof. After the change, on
Python 3.12.3/x86-64 (30 repetitions before, 200 after; same one-vote fixture):

| Check | Before, ms | Updated Python, ms | OpenSSL, ms |
|---|---:|---:|---:|
| Binary range proof | 8.022 | 6.443 | 1.298 |
| Singleton sum proof | 4.126 | 3.293 | 0.705 |
| GOST signature | 1.880 | 1.488 | 0.306 |
| TeZhu signature | 3.710 | 2.896 | 0.573 |
| Partial-decryption proof | 3.955 | 3.176 | 0.685 |
| Key aggregation | 3.069 | 1.464 | 0.293 |

No probabilistic batching, skipped equations or cached proof results are used.
The Python fallback also uses cheaper inversions, a=-3 doubling and bounded
immutable window tables. Benchmark JSON records the actual backend and runtime;
reproduce on the target host instead of treating these numbers as universal.

The seed is repeated (warm inputs), not a full-election throughput run. Corpus
CPU-hour projections omit I/O, process startup, parsing, scheduling and workload
variation; they are not wall-clock predictions. The benchmark now rejects false
verification results and sums *all* ballots when a larger fixture is selected.
No full per-ballot cryptographic audit of the EDG corpus was run as part of
this change. Separate results-only scans covered the 2024/2025 exports and all
2026 shards; they skip transaction signatures and ballot proofs, exclude a
separately established set of failed ballots, and must not be mistaken for a
full ballot audit. A Cython wrapper around Python big integers was not selected:
moving EC arithmetic to an existing native library gave the speedup without a
compiler or a custom multiprecision backend.
