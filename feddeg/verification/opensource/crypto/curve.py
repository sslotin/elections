"""ℰ — эллиптическая кривая id-tc26-gost-3410-2012-256-paramSetB.

protocol2023.pdf, §2: "ℰ – эллиптическая кривая
id-tc26-gost-3410-2012-256-paramSetB, параметры которой определены в
Рекомендациях по стандартизации Р 1323565.1.024–2019; 𝑞 – простое число,
порядок группы точек; 𝑃 – образующий элемент; 𝒪 – нейтральный элемент;
… открытые ключи являются элементами группы точек, закрытые ключи —
элементами ℤ*_𝑞. Все элементы ℤ_𝑞 представляются байтовыми строками длины 32 в
формате little-endian; точки (𝑥, 𝑦) представляются как 𝑏_𝑥‖𝑏_𝑦, где 𝑏_𝑥, 𝑏_𝑦 —
little-endian представления координат длины 32."

Parameter sources: RFC 9215 Appendix C identifies paramSetB with the earlier
CryptoPro-A curve; RFC 4357 §11.4 gives its explicit p,a,b,q,G coordinates:
https://www.rfc-editor.org/rfc/rfc9215.html#appendix-C
https://www.rfc-editor.org/rfc/rfc4357.html#section-11.4
Do not confuse this 256-bit set B with 512-bit set B or 256-bit set A.

Arithmetic references: SEC 1 v2 §2.3 (point encoding), §3.2.2 (key validation),
https://www.secg.org/sec1-v2.pdf; Bernstein & Lange's Explicit-Formulas Database,
https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
(add-2007-bl and a=-3 doubling). Two readable Python paths are kept:

* the affine one (`*_affine`, one modular inversion per operation) — slow but
  easy to read, used by the self-tests, and
* the Jacobian one used by the verifier (windowed scalar multiplication, a
  precomputed table for the generator, joint multiplication for the two-term
  equations) — the unit tests compare the two on random inputs.

For speed, FEDDEG_EC_BACKEND=auto uses OpenSSL if available; python forces the
reference path, openssl requires native support. _openssl.py only replaces
mul/mul_add/decompress, not verification rules. No Russian crypto stack or
Cython build is required. All arithmetic here is VARIABLE-TIME: public inputs
only; do not reuse these functions for signing or generating secret nonces.

Independent review checklist:
* Check p,q are prime and a=p-3,b=166,G=(1,GY). Check G is on the curve and
  q*G=infinity WITHOUT first reducing the scalar mod q. Calling mul(G,Q) is
  NOT an order test: it reduces Q to zero! Tests use raw affine additions.
  Since q is prime, G!=infinity and qG=infinity, q divides #E; the Hasse
  interval permits only the multiple q, hence cofactor=1. Thus a finite
  on-curve point is already in the prime-order subgroup on THIS fixed curve.
* Affine law is y²=x³+a*x+b mod p. Jacobian (X,Y,Z) means (X/Z²,Y/Z³), Z=0
  denotes infinity. Test infinity, doubling, equal/opposite points, negative
  and zero scalars, and full-width scalars against the independent affine law.
* Compressed points are prefix 02/03 plus x_BE32. Reject x>=p and nonsquares;
  p mod 4=3 permits sqrt via exponent (p+1)/4. Select the requested y parity.
  LE64 decoding is x_LE32||y_LE32, with both coordinates <p. Never reduce
  noncanonical incoming coordinates to silently accept a different encoding.
* Scalar multiplication reduces modulo q only for INTERNAL arithmetic. The
  signature/proof verifiers must reject out-of-range wire scalars themselves.
  Infinity may occur in sums/intermediate equations but is not an encoded
  public key in this profile. generator_walk batch-inverts only nonzero Zs.
  Precomputation caches are bounded and immutable, never cached verdicts.
"""

from __future__ import annotations

import os
from functools import lru_cache

_native = None
BACKEND = "python"

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
A = P - 3                      # a = -3 mod p
B = 0xA6
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893
GX = 1
GY = 0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14

Point = tuple[int, int] | None      # None is the neutral element 𝒪
INF = None


def is_on_curve(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    return (0 <= x < P and 0 <= y < P and
            (y * y - x * x * x - A * x - B) % P == 0)


# ------------------------------------------------------------------ affine ---

def add_affine(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def mul_affine(point: Point, scalar: int) -> Point:
    if point is None or scalar % Q == 0:
        return None
    scalar %= Q
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = add_affine(result, addend)
        addend = add_affine(addend, addend)
        scalar >>= 1
    return result


# ---------------------------------------------------------------- jacobian ---
# (X, Y, Z) stands for the affine point (X/Z², Y/Z³); Z = 0 is 𝒪.

_J_INF = (0, 1, 0)


def _to_jacobian(point: Point) -> tuple[int, int, int]:
    return _J_INF if point is None else (point[0], point[1], 1)


def _from_jacobian(point: tuple[int, int, int]) -> Point:
    x, y, z = point
    if z == 0:
        return None
    z_inv = pow(z, -1, P)
    z_inv2 = z_inv * z_inv % P
    return x * z_inv2 % P, y * z_inv2 % P * z_inv % P


def _jac_double(point: tuple[int, int, int]) -> tuple[int, int, int]:
    x, y, z = point
    if z == 0 or y == 0:
        return _J_INF
    yy = y * y % P
    yyyy = yy * yy % P
    zz = z * z % P
    s = 4 * x * yy % P
    m = 3 * (x - zz) * (x + zz) % P        # 3X² + aZ⁴, specialized to a = −3
    x3 = (m * m - 2 * s) % P
    return x3, (m * (s - x3) - 8 * yyyy) % P, 2 * y * z % P


def _jac_add(p1: tuple[int, int, int], p2: tuple[int, int, int]) -> tuple[int, int, int]:
    """add-2007-bl, with the doubling case handled."""
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 * z2z2 % P
    s2 = y2 * z1 * z1z1 % P
    if u1 == u2:
        if s1 != s2:
            return _J_INF
        return _jac_double(p1)
    h = (u2 - u1) % P
    i = (2 * h) ** 2 % P
    j = h * i % P
    r = 2 * (s2 - s1) % P
    v = u1 * i % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * s1 * j) % P
    z3 = ((z1 + z2) ** 2 - z1z1 - z2z2) * h % P
    return x3, y3, z3


_WINDOW = 4


@lru_cache(maxsize=128)
def _window_table(point: Point) -> tuple[tuple[int, int, int], ...]:
    """[𝒪, P, 2P, …, (2^w − 1)P] in Jacobian coordinates."""
    table = [_J_INF, _to_jacobian(point)]
    double = _jac_double(table[1])
    for index in range(2, 1 << _WINDOW):
        table.append(_jac_add(table[index - 1], table[1]) if index != 2
                     else double)
    return tuple(table)  # Immutable, bounded cache; repeated public keys are common.


def mul(point: Point, scalar: int) -> Point:
    """Public scalar multiplication; native or w=4 Jacobian reference path."""
    if _native is not None:
        return _native.mul(point, scalar)
    if point is None:
        return None
    scalar %= Q
    if scalar == 0:
        return None
    table = _window_table(point)
    result = _J_INF
    for shift in range(((scalar.bit_length() + _WINDOW - 1) // _WINDOW) * _WINDOW - _WINDOW,
                       -1, -_WINDOW):
        for _ in range(_WINDOW):
            result = _jac_double(result)
        digit = (scalar >> shift) & ((1 << _WINDOW) - 1)
        if digit:
            result = _jac_add(result, table[digit])
    return _from_jacobian(result)


def add(p1: Point, p2: Point) -> Point:
    return _from_jacobian(_jac_add(_to_jacobian(p1), _to_jacobian(p2)))


def neg(point: Point) -> Point:
    return None if point is None else (point[0], (-point[1]) % P)


def sub(p1: Point, p2: Point) -> Point:
    return add(p1, neg(p2))


def mul_small(point: Point, scalar: int) -> Point:
    """Compatibility helper; use the same modulo-q rules even for negatives."""
    return mul(point, scalar)


def add_many(points) -> Point:
    """Σ points, accumulating in Jacobian coordinates."""
    result = _J_INF
    for point in points:
        result = _jac_add(result, _to_jacobian(point))
    return _from_jacobian(result)


def mul_add(a: int, p1: Point, b: int, p2: Point) -> Point:
    """a·P₁ + b·P₂ with one doubling chain (Shamir's trick)."""
    if _native is not None:
        return _native.mul_add(a, p1, b, p2)
    a %= Q
    b %= Q
    if p1 is None or a == 0:
        return mul(p2, b)
    if p2 is None or b == 0:
        return mul(p1, a)
    table1 = _window_table(p1)
    table2 = _window_table(p2)
    result = _J_INF
    for shift in range(((max(a, b).bit_length() + _WINDOW - 1) // _WINDOW) * _WINDOW - _WINDOW,
                       -1, -_WINDOW):
        for _ in range(_WINDOW):
            result = _jac_double(result)
        digit1 = (a >> shift) & ((1 << _WINDOW) - 1)
        if digit1:
            result = _jac_add(result, table1[digit1])
        digit2 = (b >> shift) & ((1 << _WINDOW) - 1)
        if digit2:
            result = _jac_add(result, table2[digit2])
    return _from_jacobian(result)


# ------------------------------------------------------------- encodings ---

G: Point = (GX, GY)

def mul_generator(scalar: int) -> Point:
    """Fixed-base multiplication; mul() shares the bounded precomputation cache."""
    scalar %= Q
    if scalar == 1:
        return G
    return mul(G, scalar)


def decompress(data: bytes) -> Point:
    """33 bytes: 0x02/0x03 (y parity) then the x coordinate, big-endian."""
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError(f"not a compressed point: {data.hex()}")
    x = int.from_bytes(data[1:], "big")
    if x >= P:
        raise ValueError("x out of range")
    if _native is not None:
        return _native.decompress(data)
    value = (pow(x, 3, P) + A * x + B) % P
    y = pow(value, (P + 1) // 4, P)          # p ≡ 3 (mod 4)
    if y * y % P != value:
        raise ValueError("x is not on the curve")
    if (y & 1) != (data[0] & 1):
        y = P - y
    return x, y


def compress(point: Point) -> bytes:
    if point is None:
        raise ValueError("𝒪 has no compressed form here")
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def from_le_xy(data: bytes) -> Point:
    """Bit-string representation of a point: x ‖ y, both little-endian."""
    if len(data) != 64:
        raise ValueError("expected 64 bytes")
    x = int.from_bytes(data[:32], "little")
    y = int.from_bytes(data[32:], "little")
    if not (0 <= x < P and 0 <= y < P):
        raise ValueError("point coordinates out of range")
    if not is_on_curve((x, y)):
        raise ValueError("point not on the curve")
    return x, y


def to_le_xy(point: Point) -> bytes:
    x, y = point
    return x.to_bytes(32, "little") + y.to_bytes(32, "little")


def generator_walk(limit: int):
    """Yield 0·G through limit·G, using bounded Montgomery batch inversion."""
    cursor = _J_INF
    generator = _to_jacobian(G)
    for start in range(0, limit + 1, 128):
        batch = []
        prefixes = []
        product = 1
        for _ in range(min(128, limit + 1 - start)):
            batch.append(cursor)
            prefixes.append(product)
            if cursor[2]:
                product = product * cursor[2] % P
            cursor = _jac_add(cursor, generator)
        inverse = pow(product, -1, P)
        affine = [None] * len(batch)
        for index in range(len(batch) - 1, -1, -1):
            x, y, z = batch[index]
            if z:
                zi = inverse * prefixes[index] % P
                inverse = inverse * z % P
                zi2 = zi * zi % P
                affine[index] = (x * zi2 % P, y * zi2 * zi % P)
        yield from affine


def check_generator_order() -> bool:
    """Raw q*G check; deliberately bypass scalar reduction in all mul helpers."""
    result = _J_INF
    for bit in bin(Q)[2:]:
        result = _jac_double(result)
        if bit == "1":
            result = _jac_add(result, _to_jacobian(G))
    return is_on_curve(G) and G is not None and result[2] == 0


# Optional acceleration is selected once per process (also on spawn-based pools).
# Missing native support may fall back; arithmetic/runtime failures never do.
_requested_backend = os.environ.get("FEDDEG_EC_BACKEND", "auto")
if _requested_backend not in {"auto", "python", "openssl"}:
    raise ValueError("FEDDEG_EC_BACKEND must be auto, python or openssl")
if _requested_backend != "python":
    try:
        from ._openssl import OpenSSLCurve
        _native = OpenSSLCurve(P, A, B, Q, G)
    except (OSError, AttributeError) as error:
        if _requested_backend == "openssl":
            raise RuntimeError("requested OpenSSL EC backend is unavailable") from error
    else:
        BACKEND = "openssl"
