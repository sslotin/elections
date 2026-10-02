"""S — схема подписи ГОСТ Р 34.10-2012 (§2.2 протокола).

protocol2023.pdf, §2.2: "Схема подписи 𝑆 … (используется схема, определенная
стандартом ГОСТ Р 34.10–2012 [1])" with 𝐻 = Стрибог-256 and the curve of §2.
Primary specification: RFC 7091 §6.2, Algorithm II, steps 1–7 (the public
English version of ГОСТ Р 34.10-2012, not a different signature scheme):
https://www.rfc-editor.org/rfc/rfc7091.html#section-6.2
Verification is implemented straight from that algorithm:

    e = h(M) mod q                     (h as an integer)
    v = e⁻¹ mod q
    z₁ = s·v mod q,  z₂ = −r·v mod q
    C = z₁·P + z₂·Q
    проверка: x_C mod q == r

Independent review, in order: validate a finite canonical on-curve public key
(cofactor 1); require exactly 64 signature bytes; require 0<r,s<q BEFORE scalar
multiplication. Compute e from Streebog(message); replace zero e with one;
compute v by a modular inverse; evaluate BOTH scalar terms and reject infinity;
compare x_C MOD q (not mod p) with r. For a positive synthetic check, take
Q=dG, R=kG, r=x_R mod q, s=r*d+k*e mod q; the verification point must be kG.
Test wrong message/key, zero/out-of-range scalars, zero digest and infinity.

Wire profile: chain signatures are s_BE32||r_BE32, while RFC 7091's abstract
bit-vector notation is R||S. libgcrypt's digest bytes are interpreted LITTLE-
endian here. Do not infer these two independent byte orders from one another.
`swap_rs` and `digest_le` exist for explicit diagnostic comparisons, not for
trying alternatives until an invalid signature passes. Real-export regressions
pin the default profile. RFC 7091 §7 uses a DIFFERENT example curve, so its
signature vector cannot be pasted into this fixed-paramSetB implementation.

The signed message is produced by bulletin.transaction_bytes: it binds request
parameters, not exported state diffs, acceptance flags, voter eligibility or
chain membership. This check does not verify block consensus or the export's
completeness. The serializer itself needs independent chain-format review.
"""

from __future__ import annotations

from . import curve
from .streebog import streebog256


def verify(public_key: curve.Point, message: bytes, signature: bytes, *,
           digest_le: bool = True, swap_rs: bool = True) -> bool:
    """S.Verify with the wire conventions pinned by the public-export tests.

    Digest bytes are LE, signature is s_BE32||r_BE32. See the module review
    checklist; diagnostic convention flags must not be auto-negotiated.
    """
    if (public_key is None or not curve.is_on_curve(public_key)
            or len(signature) != 64):
        return False
    first, second = signature[:32], signature[32:]
    if swap_rs:
        first, second = second, first
    r = int.from_bytes(first, "big")
    s = int.from_bytes(second, "big")
    if not (0 < r < curve.Q and 0 < s < curve.Q):
        return False

    digest = streebog256(message)
    e = int.from_bytes(digest, "little" if digest_le else "big") % curve.Q
    if e == 0:
        e = 1
    v = pow(e, -1, curve.Q)
    c = curve.mul_add(s * v % curve.Q, curve.G, (-r * v) % curve.Q, public_key)
    if c is None:
        return False
    return c[0] % curve.Q == r
