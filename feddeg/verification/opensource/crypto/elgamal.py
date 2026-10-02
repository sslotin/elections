"""SE — гомоморфное сложение, агрегирование ключей и расшифрование (§2.4).

Sources:
* ElGamal, "A Public Key Cryptosystem and a Signature Scheme Based on Discrete
  Logarithms", IEEE TIT 31(4), 1985, https://doi.org/10.1109/TIT.1985.1057074
  (encryption, not the ElGamal signature algorithm).
* Cramer, Gennaro & Schoenmakers, "A Secure and Optimally Efficient
  Multi-Authority Election Scheme", EUROCRYPT '97, §§2.3–2.6 and 3:
  https://crypto.ethz.ch/publications/files/CrGeSc97b.pdf — exponential ElGamal,
  homomorphic tallying, proofs of valid votes and partial decryptions.
* ../../protocol/protocol2023.pdf §2.4, raster formulas 05, 10, 15 in
  ../../protocol/protocol2023-assets/ — the scheme-specific key weights.

The production arithmetic is (G is the PDF's generator P):

    KeyAgg:  pk = h(pk₁‖pk₂)·pk₁ + h(pk₂‖pk₁)·pk₂,  h = Hash into ℤ_q
    Add:     (ΣA_i, ΣB_i) componentwise, per cell
    DecAgg:  V = B̄ − h(pk₁‖pk₂)·P₁ − h(pk₂‖pk₁)·P₂ with P_j = sk_j·Ā published
             in the partial decryptions, then the discrete logarithm V = v·P
             gives the tally v (v ≤ number of accepted ballots, so it is solved
             by enumeration).

Independent derivation: if pk_i=x_i*G and pk=h1*pk1+h2*pk2, one ciphertext
is A=r*G, B=r*pk+m*G. Componentwise summation gives Abar=(sum r)*G and
Bbar=(sum r)*pk+(sum m)*G. Authority i publishes P_i=x_i*Abar, which zkp.py
must verify BEFORE it is trusted. Then Bbar-h1*P_1-h2*P_2=(sum m)*G.
Use the SAME coefficients, key order and hash encoding in KeyAgg and DecAgg.
Do not replace them by unweighted key addition or cite a generic multisignature
paper as a proof of this specific two-key construction.

IMPORTANT PDF discrepancy: the PDF explicitly sets h1=H(pk2||pk1),
h2=H(pk1||pk2), the OPPOSITE assignment from production above. Its general
point encoding is LE64; production hashfn.points_hash uses compressed ASCII
hex. The implemented order is pinned by actual exports and by:
https://github.com/cikrf/deg2025/blob/d1fc451622342990e436afdc5849e6e9969f62c7/observer-tools/src/worker/index.ts
(calculateResults), plus src/worker/worker.ts (encryptedSums). Matching those
sources demonstrates compatibility, not exact PDF conformance or a security
reduction for the hash-weighted key setup.

Review obligations outside the group equations:
* Include each accepted voter key once, require identical ballot dimensions,
  and stop short of certifying a tally if ANY included ballot check fails.
* Per-option proofs establish m in {0,1}, so each tally lies in [0,N]. Search
  only this interval, require N<q for uniqueness, compare the FULL point (x
  alone confuses vG with -vG), preserve duplicate targets, and map infinity to
  zero. Missing solutions stay None, never zero. Compare the full tally shape
  and all entries with published RESULTS. A bounded walk uses O(number of
  target cells) memory, not a table proportional to all ballots.
* These helpers only do arithmetic. They do not verify proofs, authenticate
  authority identities, reconstruct DKG, or prove honest key generation.
  Protocol drivers perform proof checks and track incomplete/failing results.
"""

from __future__ import annotations

from . import curve
from .hashfn import points_hash_mod_q

Ciphertext = tuple[curve.Point, curve.Point]


class CiphertextAccumulator:
    """Streaming homomorphic sum without retaining every ballot.

    ``curve.add_many`` is efficient for a known finite list, but a raw dump
    interleaves elections and may contain millions of ballots.  This
    accumulator keeps one Jacobian point per ciphertext cell and converts to
    affine coordinates only once, at the end of an election.
    """

    def __init__(self, shape: list[int]) -> None:
        if not shape or any(count <= 0 for count in shape):
            raise ValueError("invalid ciphertext shape")
        self.shape = list(shape)
        self._points = [
            [(curve._J_INF, curve._J_INF) for _ in range(count)]
            for count in shape
        ]
        self.count = 0

    def add(self, bulletin: list[list[Ciphertext]]) -> None:
        if [len(question) for question in bulletin] != self.shape:
            raise ValueError("inconsistent bulletin dimensions")
        for question_index, question in enumerate(bulletin):
            for cell_index, (a_point, b_point) in enumerate(question):
                a, b = self._points[question_index][cell_index]
                self._points[question_index][cell_index] = (
                    curve._jac_add(a, curve._to_jacobian(a_point)),
                    curve._jac_add(b, curve._to_jacobian(b_point)),
                )
        self.count += 1

    def finish(self) -> list[list[Ciphertext]]:
        if self.count == 0:
            raise ValueError("cannot finish an empty ciphertext sum")
        return [
            [
                (curve._from_jacobian(a), curve._from_jacobian(b))
                for a, b in question
            ]
            for question in self._points
        ]


def key_agg(pk1: curve.Point, pk2: curve.Point) -> curve.Point:
    """SE.KeyAgg — the ballot encryption key of a voting (§4.2.3)."""
    h1 = points_hash_mod_q([pk1, pk2])
    h2 = points_hash_mod_q([pk2, pk1])
    return curve.mul_add(h1, pk1, h2, pk2)


def add(ciphertexts: list[list[list[Ciphertext]]]) -> list[list[Ciphertext]]:
    """SE.Add — homomorphic addition of whole bulletins (per question/cell)."""
    if not ciphertexts:
        raise ValueError("nothing to add")
    shape = [len(question) for question in ciphertexts[0]]
    if any([len(q) for q in ballot] != shape for ballot in ciphertexts):
        raise ValueError("inconsistent bulletin dimensions")
    return [[(curve.add_many(ballot[q][c][0] for ballot in ciphertexts),
              curve.add_many(ballot[q][c][1] for ballot in ciphertexts))
             for c in range(count)] for q, count in enumerate(shape)]


def dec_agg(summed: list[Ciphertext], partials: list[tuple[dict, dict]], pk1: curve.Point,
            pk2: curve.Point, *, limit: int) -> list[int | None]:
    """SE.DecAgg arithmetic only; callers must verify partial proofs first."""
    if len(summed) != len(partials):
        raise ValueError("partial decryptions do not match ciphertext count")
    h1 = points_hash_mod_q([pk1, pk2])
    h2 = points_hash_mod_q([pk2, pk1])
    targets = [curve.sub(b_point, curve.mul_add(h1, _point(master["P"]),
                                               h2, _point(commission["P"])))
               for (_, b_point), (master, commission) in zip(summed, partials)]
    solved = solve_dlp_batch(targets, limit)
    return [solved[index] for index in range(len(targets))]


def _point(value) -> curve.Point:
    if isinstance(value, str):
        return curve.decompress(bytes.fromhex(value))
    return curve.decompress(value)


def solve_dlp(point: curve.Point, limit: int) -> int | None:
    """Smallest v in [0,limit] with point=vG; never search without a bound."""
    return solve_dlp_batch([point], limit)[0]


def solve_dlp_batch(points: list[curve.Point | None], limit: int) -> dict[int, int | None]:
    """One linear walk resolved against all targets at once (all tallies share it)."""
    if type(limit) is not int or not 0 <= limit < curve.Q:
        raise ValueError("DLP limit must be an integer in [0,q)")
    wanted: dict[curve.Point, list[int]] = {}
    found: dict[int, int | None] = {}
    for index, point in enumerate(points):
        found[index] = 0 if point is None else None
        if point is not None:
            wanted.setdefault(point, []).append(index)
    if not wanted:
        return found
    for value, cursor in enumerate(curve.generator_walk(limit)):
        for index in wanted.pop(cursor, []):
            found[index] = value
        if not wanted:
            break
    return found
