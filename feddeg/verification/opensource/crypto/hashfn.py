"""Hash(m, DST) — the hash-to-field function of the protocol.

protocol2023.pdf, §2.1: "Хэш-функция, отображающая двоичные строки конечной длины
в элементы конечного поля ℤ_𝑞, определяется функцией 𝐻𝑎𝑠ℎ. Вход: сообщение 𝑚,
идентификатор области применения 𝐷𝑆𝑇 длины 𝑙 байт. Выход: хэш-значение ℎ ∈ ℤ_𝑞."
The construction IS specified in the PDF's raster formula (not its extracted
text): ../../protocol/protocol2023-assets/00-hash.png. It is expand_message_xmd
with Streebog-256, 64-byte hash block size, 32-byte digest and output L=48.
Compare RFC 9380 §5.3.1 steps 1–11 and §5.2 (hash_to_field):
https://www.rfc-editor.org/rfc/rfc9380.html#section-5.3.1
Streebog is this protocol's instantiation, not a standardized RFC 9380 suite.

Two helpers are needed by the schemes of §2.3–2.4:

* `xmd_ro(message, dst)` — the expand_message_xmd-style construction used by the
  blind signature and partial-decryption proof (dst takes DST_prime);
* `points_hash(points)` — the range-proof challenge and key-aggregation hash,
  NOT the production partial-decryption proof challenge.

Independent byte-level reconstruction (|| is byte concatenation):
  DST_prime = DST || I2OSP(len(DST),1)           # length in BYTES
  b0 = H(0^64 || message || I2OSP(L,2) || 0x00 || DST_prime)
  b1 = H(b0 || 0x01 || DST_prime)
  b2 = H((b0 XOR b1) || 0x02 || DST_prime)
  scalar = OS2IP_BE((b1||b2)[:48]) mod q
For smaller requested L, bind that L into b0, compute ceil(L/32) blocks and
truncate only at the end. This helper supports 1..64 bytes, not arbitrary RFC
suites/long-DST processing. `dst` is ALREADY DST_prime: never append its length
twice. DST_BLIND has length 80, hence the final ASCII P in DST_BLIND_ROP is a
length byte, not a distinct cipher suite name. Diagnostic legacy callers may
explicitly supply the unsuffixed domain, but the default is the proper one.

points_hash is DIFFERENT: concatenate the lowercase hex of each 33-byte
compressed point, encode that string as ASCII, Streebog-256 it, interpret the
32 digest bytes big-endian, optionally reduce mod q. Each point contributes 66
ASCII bytes, without separators; do not hash the 33 raw bytes or LE64 points.
The order of points is protocol-significant. See zkp.py and elgamal.py for
known PDF/production discrepancies. Evidence: the pinned deg2025 revision in
zkp.py, observer-tools/src/utils/utils.ts (hashPoints) and lib/curve.c.
Tests should reconstruct the XMD blocks independently, not merely call this
function twice; real-proof acceptance is a compatibility check, not a proof
that the chosen hash instantiation satisfies random-oracle assumptions.
"""

from __future__ import annotations

from . import curve
from .streebog import streebog256

DST_BLIND = (b"BlindSign-TeZhu-V00-H2F:id-tc26-gost-3410-2012-256-paramSetB"
             b"_Streebog-256_XMD_RO")
DST_BLIND_ROP = DST_BLIND + bytes([len(DST_BLIND)])  # RFC 9380 DST_prime (80 = ASCII P)
DST_DP = (b"ZKP-CP-eqdlog-V00-H2F:id-tc26-gost-3410-2012-256-paramSetB"
          b"_Streebog-256_XMD_RO")
DST_DP_PRIME = DST_DP + bytes([len(DST_DP)])


def xmd_ro(message: bytes, dst: bytes = DST_BLIND_ROP, length: int = 48) -> bytes:
    """XMD expansion; `dst` is the already length-suffixed DST_prime."""
    if not 0 < length <= 64:
        raise ValueError("this instantiation produces up to 64 bytes")
    blocks = (length + 31) // 32
    seed = (b"\x00" * 64 + message
            + (length >> 8).to_bytes(1, "big") + (length & 0xFF).to_bytes(1, "big")
            + b"\x00" + dst)
    first = streebog256(seed)
    previous = b"\x00" * 32
    out = b""
    for index in range(1, blocks + 1):
        previous = streebog256(bytes(a ^ b for a, b in zip(previous, first))
                               + bytes([index]) + dst)
        out += previous
    return out[:length]


def xmd_ro_scalar(message: bytes, dst: bytes = DST_BLIND_ROP) -> int:
    return int.from_bytes(xmd_ro(message, dst), "big") % curve.Q


def points_hash(points: list[curve.Point]) -> int:
    """H over a list of points: Streebog-256 of their lowercase hex encoding."""
    source = b"".join(curve.compress(point).hex().encode() for point in points)
    return int.from_bytes(streebog256(source), "big")


def points_hash_mod_q(points: list[curve.Point]) -> int:
    return points_hash(points) % curve.Q
