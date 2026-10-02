"""H — функция хэширования ГОСТ Р 34.11-2012 (Стрибог), 256 бит.

protocol2023.pdf, §2: "𝐻 – хэш-функция Стрибог с длиной выхода 256 битов,
определенная в стандарте ГОСТ Р 34.11–2012 [2]".

Primary specification: https://www.rfc-editor.org/rfc/rfc6986.html
§§6–9 specify the compression/iteration construction; §§10.1.2 and 10.2.2
supply 256-bit known-answer examples (do not use the 512-bit examples).

This module delegates the HASH ONLY to libgcrypt (GnuPG), algorithm STRIBOG256
(ID 309); it is not a Python reimplementation of the compression function.
Independent verification: check algorithm availability, hash exact bytes with
explicit length (embedded NULs must not truncate), and require exactly 32
output bytes. RFC bit-vector display order differs from the byte-oriented API;
tests/test_crypto.py pins both published examples in libgcrypt's byte order.
Do not reverse the returned digest globally: GOST signatures read it as LE,
whereas points_hash/XMD read output as BE. Their own callers choose that rule.
A known-answer test checks implementation compatibility, not collision or
preimage resistance; the protocol assumes the hash has those properties.
"""

from __future__ import annotations

import ctypes
import os
from ctypes.util import find_library

GCRY_MD_STRIBOG256 = 309

# ``find_library`` keeps the verifier usable with libgcrypt's usual Linux,
# macOS and Windows library names.  The algorithm is the same; only the
# dynamic-loader spelling differs by platform.
_library_name = find_library("gcrypt") or next((name for name in (
    "libgcrypt.so.20", "libgcrypt.dylib", "libgcrypt-20.dll"
) if os.path.exists(name)), None)
if _library_name is None:
    raise RuntimeError("libgcrypt with STRIBOG256 is required")
_gcrypt = ctypes.CDLL(_library_name)
_gcrypt.gcry_check_version.restype = ctypes.c_char_p
_gcrypt.gcry_check_version.argtypes = [ctypes.c_char_p]
_gcrypt.gcry_md_map_name.restype = ctypes.c_int
_gcrypt.gcry_md_map_name.argtypes = [ctypes.c_char_p]
_gcrypt.gcry_md_hash_buffer.restype = None
_gcrypt.gcry_md_hash_buffer.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                     ctypes.c_char_p, ctypes.c_size_t]
_gcrypt.gcry_check_version(None)
ALG = _gcrypt.gcry_md_map_name(b"STRIBOG256")
if ALG != GCRY_MD_STRIBOG256:
    raise RuntimeError(f"libgcrypt has no STRIBOG256: {ALG}")


def streebog256(data: bytes) -> bytes:
    """GOST R 34.11-2012, 256-bit output."""
    out = ctypes.create_string_buffer(32)
    _gcrypt.gcry_md_hash_buffer(ALG, out, data, len(data))
    return out.raw


def streebog256_int(data: bytes) -> int:
    """The 32-byte digest as an integer (big-endian, as the implementations do)."""
    return int.from_bytes(streebog256(data), "big")
