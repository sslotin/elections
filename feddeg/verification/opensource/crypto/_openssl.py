"""Optional generic EC arithmetic through OpenSSL's public libcrypto API.

This is NOT OpenSSL's GOST signature implementation: only point arithmetic is
native; all protocol equations, encodings, hashes and rejection rules remain
in Python. API reference: https://docs.openssl.org/3.0/man3/EC_POINT_add/
and https://docs.openssl.org/3.0/man3/EC_GROUP_new/. EC_POINTs_mul is deprecated
in OpenSSL 3 but still exported by ordinary builds; builds without it use the
Python backend. No Cython/compiler, GOST engine or curve-name registry needed.

Ownership: the immutable group lives with this object; every operation has its
own BN_CTX and frees all temporary BIGNUMs/points, including on error. No C
pointers cross process boundaries. Inputs/outputs are Python ints/tuples.
Variable-time arithmetic is appropriate ONLY for public verification data.
"""

from __future__ import annotations

import ctypes as c
from contextlib import ExitStack
from ctypes.util import find_library
from weakref import finalize


class OpenSSLCurve:
    def __init__(self, p: int, a: int, b: int, order: int, generator: tuple[int, int]):
        name = find_library("crypto")
        if not name:
            raise OSError("OpenSSL libcrypto not found")
        self.lib = lib = c.CDLL(name)
        ptr, integer, size = c.c_void_p, c.c_int, c.c_size_t
        # Explicit signatures are essential: ctypes otherwise truncates pointers.
        signatures = {
            "BN_CTX_new": (ptr, []), "BN_CTX_free": (None, [ptr]),
            "BN_bin2bn": (ptr, [c.c_char_p, integer, ptr]),
            "BN_free": (None, [ptr]),
            "EC_GROUP_new_curve_GFp": (ptr, [ptr, ptr, ptr, ptr]),
            "EC_GROUP_free": (None, [ptr]),
            "EC_GROUP_set_generator": (integer, [ptr, ptr, ptr, ptr]),
            "EC_GROUP_check": (integer, [ptr, ptr]),
            "EC_POINT_new": (ptr, [ptr]), "EC_POINT_free": (None, [ptr]),
            "EC_POINT_oct2point": (integer, [ptr, ptr, c.c_char_p, size, ptr]),
            "EC_POINT_point2oct": (size, [ptr, ptr, integer, c.c_void_p, size, ptr]),
            "EC_POINT_mul": (integer, [ptr, ptr, ptr, ptr, ptr, ptr]),
            "EC_POINTs_mul": (integer, [ptr, ptr, ptr, size,
                                        c.POINTER(ptr), c.POINTER(ptr), ptr]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(lib, name)  # AttributeError means unavailable backend.
            function.restype, function.argtypes = result, args
        self.order, self.generator = order, generator
        with _Operation(self) as op:
            self.group = _allocated(lib.EC_GROUP_new_curve_GFp(
                op.bn(p), op.bn(a), op.bn(b), op.ctx))
            self._free = finalize(self, lib.EC_GROUP_free, self.group)
            try:
                _ok(lib.EC_GROUP_set_generator(self.group, op.point(generator),
                                               op.bn(order), op.bn(1)))
                # Independent native check of discriminant, generator and q*G=O.
                _ok(lib.EC_GROUP_check(self.group, op.ctx))
            except BaseException:
                self._free()
                raise

    def decompress(self, encoded):
        with _Operation(self) as op:
            point = op.point()
            if self.lib.EC_POINT_oct2point(self.group, point, encoded, len(encoded), op.ctx) != 1:
                raise ValueError("compressed point is not on the curve")
            return op.affine(point)

    def mul(self, point, scalar):
        scalar %= self.order
        if point is None or scalar == 0:
            return None
        if scalar == 1:
            return point
        with _Operation(self) as op:
            result = op.point()
            if point == self.generator:
                _ok(self.lib.EC_POINT_mul(self.group, result, op.bn(scalar), None, None, op.ctx))
            else:
                _ok(self.lib.EC_POINT_mul(self.group, result, None, op.point(point),
                                          op.bn(scalar), op.ctx))
            return op.affine(result)

    def mul_add(self, a, p1, b, p2):
        a, b = a % self.order, b % self.order
        if p1 is None or a == 0:
            return self.mul(p2, b)
        if p2 is None or b == 0:
            return self.mul(p1, a)
        if p2 == self.generator:
            a, p1, b, p2 = b, p2, a, p1
        with _Operation(self) as op:
            result = op.point()
            if p1 == self.generator:
                _ok(self.lib.EC_POINT_mul(self.group, result, op.bn(a), op.point(p2),
                                          op.bn(b), op.ctx))
            else:
                points = (c.c_void_p * 2)(op.point(p1), op.point(p2))
                scalars = (c.c_void_p * 2)(op.bn(a), op.bn(b))
                _ok(self.lib.EC_POINTs_mul(self.group, result, None, 2, points, scalars, op.ctx))
            return op.affine(result)


def _allocated(pointer):
    if not pointer:
        raise MemoryError("OpenSSL allocation failed")
    return pointer


def _ok(status):
    if status != 1:
        # Never silently retry arithmetic with another backend on runtime errors.
        raise RuntimeError("OpenSSL EC operation failed")


class _Operation(ExitStack):
    def __init__(self, curve):
        super().__init__()
        self.curve, self.lib = curve, curve.lib
        self.ctx = _allocated(self.lib.BN_CTX_new())
        self.callback(self.lib.BN_CTX_free, self.ctx)

    def bn(self, value):
        encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        pointer = _allocated(self.lib.BN_bin2bn(encoded, len(encoded), None))
        self.callback(self.lib.BN_free, pointer)
        return pointer

    def point(self, value=None):
        pointer = _allocated(self.lib.EC_POINT_new(self.curve.group))
        self.callback(self.lib.EC_POINT_free, pointer)
        if value is not None:
            # Uncompressed import avoids repeating square roots for validated points.
            x, y = value
            encoded = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
            _ok(self.lib.EC_POINT_oct2point(self.curve.group, pointer, encoded, len(encoded), self.ctx))
        return pointer

    def affine(self, point):
        encoded = c.create_string_buffer(65)
        size = self.lib.EC_POINT_point2oct(self.curve.group, point, 4, encoded, 65, self.ctx)
        if size == 1 and encoded.raw[0] == 0:  # SEC 1 encoding of infinity.
            return None
        if size != 65 or encoded.raw[0] != 4:
            raise RuntimeError("OpenSSL returned an invalid affine encoding")
        return int.from_bytes(encoded.raw[1:33], "big"), int.from_bytes(encoded.raw[33:], "big")
