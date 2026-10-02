"""SE — special encryption scheme and its zero-knowledge proofs (§2.4 протокола).

Sources (read these before comparing equations):
* Chaum & Pedersen, "Wallet Databases with Observers", CRYPTO '92,
  https://doi.org/10.1007/3-540-48071-4_7 — equality of discrete logarithms.
* Cramer, Damgård & Schoenmakers, "Proofs of Partial Knowledge and Simplified
  Design of Witness Hiding Protocols", EUROCRYPT '94 (not CRYPTO '94),
  https://doi.org/10.1007/3-540-48658-5_19 — OR composition, sum of challenges.
* Fiat & Shamir, "How To Prove Yourself", CRYPTO '86,
  https://doi.org/10.1007/3-540-47721-7_12 — replace the interactive challenge
  with a hash. These are OR membership proofs, NOT Bulletproofs.
* ../../protocol/protocol2023.pdf §2.4; formula images
  07-encryption-rprove.png, 09-encryption-rverify.png, 14-decryption-dverify.png
  in ../../protocol/protocol2023-assets/.

Notation: this module's G is the PDF's generator P; (A,B) is its (R,C),
public_key is Q, and As/Bs are commitments, NOT additional ciphertexts.
The production decryption domain is
Hash_DP(m) = Hash(m, DST_DP) and
DST_DP = «ZKP-CP-eqdlog-V00-H2F:id-tc26-gost-3410-2012-256-paramSetB_Streebog-256_XMD_RO».

Ciphertexts and proofs use the structure of the protocol:

    c_j = (A_j, B_j) = (r_j·P, r_j·PK + m_j·P)          (one cell per option)
    range proof for a cell: (A, B, A_s[1..k], B_s[1..k], c[1..k], r[1..k])

`verify_range_proof` checks exactly the two relations of the disjunctive
Chaum–Pedersen proof for each allowed plaintext m_i of the cell and the
Fiat–Shamir challenge over the whole statement:

    r_i·P     == A_s[i] + c_i·A
    r_i·PK    == B_s[i] + c_i·(B − m_i·P)
    Σ c_i     ≡  H(PK, A, B, A_s…, B_s…)  (mod q)

`verify_decryption` checks the Chaum–Pedersen proof π of a partial decryption
(§4.5.4): with P' = sk_part·A the prover publishes (P', w, U1, U2) and

    v = XMD(pollId || LE(U1, U2, A, P', P, PK_part), DST_DP_prime)
    w·A     == v·P'      + U1
    w·P     == v·PK_part + U2

(`P` is the generator; `U1 = u·A`, `U2 = u·P`). Completeness follows by
substituting w = u + v*sk_part into both equations.

Independent review checklist
----------------------------
1. Decode finite on-curve points (cofactor 1) and canonical scalars BEFORE any
   multiplication reduces modulo q. Range scalars and decryption w are 32-byte
   BIG-endian, unlike the PDF's general LE convention and TeZhu's LE scalars.
2. For each branch i, let D_i = B - m_i*G. The relation is
   log_G(A) = log_PK(D_i). An honest branch with encryption nonce rho has
   r_i = u_i + c_i*rho; substituting yields both equations above. Simulated
   branches choose c_i,r_i first and derive As_i,Bs_i. ONLY the sum challenge
   ties them together, so checking equations without the hash is insufficient.
3. Compare the hash to sum(c_i) mod q, then check EVERY branch's TWO equations.
   mul_add(r,G,-c,A) is exactly rG-cA, not a probabilistic batch test. Branches
   must be in the caller's declared order [0,1] or [min,...,max]. See hashfn.py
   for exact bytes; malformed sizes raise ProofError, invalid equations return
   False. Zero c_i/r_i are rejected as required by PDF Rverify.
4. Per-cell membership is insufficient for a ballot: protocol._ballot must
   separately bind the sum ciphertext to the componentwise sum of options.
5. For decryption, prove log_A(partial) = log_G(public_key), with transcript
   UTF8(pollId)||LE64(U1)||LE64(U2)||LE64(A)||LE64(partial)||LE64(G)||LE64(PK).
   LE64 means x_LE32||y_LE32. XMD returns 48 bytes interpreted BIG-endian mod q;
   w may be zero. B is intentionally absent: decryption depends only on A;
   elgamal.DecAgg later subtracts the authenticated partials from B. Changing
   pollId, PK, A, P, U1, U2 or w must invalidate a normal proof.

PDF/production discrepancy: PDF Rverify hashes P||Q||R||C||Astr||Bstr.
Production omits the generator and hashes ASCII lowercase compressed-point
hex, not the PDF's LE coordinates. We verify the deployed profile, not exact
PDF conformance. Public implementation evidence (not a security proof):
https://github.com/cikrf/deg2025/blob/d1fc451622342990e436afdc5849e6e9969f62c7/observer-tools/lib/curve.c
function VerifyRangeProofExCompressedCryptoPro. Do NOT change the transcript
silently: doing so rejects real proofs and defines a different protocol.

Soundness assumes discrete-log hardness and suitable random-oracle behavior
of the domain-separated hashes. Passing proofs do not authenticate the key
owners, prove voter eligibility, or establish honest nonce generation.
"""

from __future__ import annotations

from . import curve
from .hashfn import DST_DP_PRIME, points_hash_mod_q, xmd_ro


class ProofError(ValueError):
    pass


def verify_range_proof(public_key: curve.Point, messages: list[int], cell: dict) -> bool:
    """The disjunctive Chaum–Pedersen proof that the plaintext is in `messages`."""
    if (not messages or any(type(m) is not int or not 0 <= m < curve.Q for m in messages)
            or len(set(messages)) != len(messages)):
        raise ProofError("messages must be distinct canonical nonnegative scalars")
    if any(len(cell[key]) != len(messages) for key in ("As", "Bs", "c", "r")):
        raise ProofError("range proof does not cover the declared message set")
    if any(len(value) != 32 for key in ("c", "r") for value in cell[key]):
        raise ProofError("range proof scalars must be 32 bytes")
    challenges = [int.from_bytes(value, "big") for value in cell["c"]]
    responses = [int.from_bytes(value, "big") for value in cell["r"]]
    if (public_key is None or not curve.is_on_curve(public_key)
            or any(not 0 < value < curve.Q for value in challenges + responses)):
        return False
    a_point = curve.decompress(cell["A"])
    b_point = curve.decompress(cell["B"])
    as_points = [curve.decompress(p) for p in cell["As"]]
    bs_points = [curve.decompress(p) for p in cell["Bs"]]
    # Cheap rejection first; acceptance still requires every group equation.
    expected = points_hash_mod_q([public_key, a_point, b_point] + as_points + bs_points)
    if sum(challenges) % curve.Q != expected:
        return False
    for index, plaintext in enumerate(messages):
        challenge, response = challenges[index], responses[index]
        # Rearrange each equation into a two-scalar multiplication; no batching.
        if curve.mul_add(response, curve.G, -challenge, a_point) != as_points[index]:
            return False
        shifted = curve.sub(b_point, curve.mul_generator(plaintext))
        if curve.mul_add(response, public_key, -challenge, shifted) != bs_points[index]:
            return False

    return True


def verify_decryption(public_key: curve.Point, ciphertext: tuple[curve.Point, curve.Point],
                      proof: dict, *, poll_id: str) -> bool:
    """SE.VerifyDecPart — Chaum–Pedersen proof for one partially decrypted cell.

    `proof` holds P (the partial decryption), w, U1, U2 as hex strings.
    `poll_id` is the voting identifier, authenticated as part of the challenge.
    """
    if public_key is None or not curve.is_on_curve(public_key):
        return False
    if not isinstance(poll_id, str) or not poll_id:
        raise ProofError("poll_id must be a nonempty string")
    if ciphertext[0] is None or not curve.is_on_curve(ciphertext[0]):
        raise ProofError("decryption base must be a finite curve point")
    encoded = {key: bytes.fromhex(proof[key]) if isinstance(proof[key], str)
               else proof[key] for key in ("P", "w", "U1", "U2")}
    if len(encoded["w"]) != 32:
        raise ProofError("decryption response must be 32 bytes")
    partial = curve.decompress(encoded["P"])
    w = int.from_bytes(encoded["w"], "big")
    u1 = curve.decompress(encoded["U1"])
    u2 = curve.decompress(encoded["U2"])
    a_point, _ = ciphertext

    if not 0 <= w < curve.Q:
        return False
    # Production transcript, independently matched to CSP hash-call traces.
    # xmd_ro accepts DST_prime, including RFC 9380's one-byte DST length.
    statement = poll_id.encode() + b"".join(curve.to_le_xy(point) for point in
                                           [u1, u2, a_point, partial, curve.G, public_key])
    challenge = int.from_bytes(xmd_ro(statement, DST_DP_PRIME), "big") % curve.Q
    return (curve.mul_add(w, a_point, -challenge, partial) == u1 and
            curve.mul_add(w, curve.G, -challenge, public_key) == u2)
