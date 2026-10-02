"""Decoding of the on-chain structures that carry the protocol's objects.

Two encodings are *not* described by protocol2023.pdf and come from the public
implementations / chain format:

* the protobuf `Bulletin`/`Question`/`RangeProof` envelope that carries
  `(c₁,…,c_t)` and the proofs of SE.Enc (vote.proto), and
* the transaction byte string that is signed with S.Sign (§4.4.1) — the protocol
  only lists the fields of 𝑡𝑥, not their serialisation.

Keeping them in one module makes the boundary between "specified by the
protocol" and "chain plumbing" explicit. This is serialization, not a new
cryptographic construction; the GOST paper/standard does not define these bytes.

Independent review sources: protobuf wire specification,
https://protobuf.dev/programming-guides/encoding/; the public implementation
https://github.com/cikrf/deg2025/tree/d1fc451622342990e436afdc5849e6e9969f62c7/observer-tools/src
(utils/get-tx-bytes.ts and utils/byte-utils.ts for transaction bytes; the
Bulletin schema is consumed by the worker's protobuf decoder). Compare
transaction fields IN ORDER, widths, endianness, type/version-specific suffixes,
Base58 leading zeros, and signed-string UTF8 bytes, not just parsed JSON values.
Our serializer supports only zero-fee exports; unsupported types/fees fail.

The decoder checks length bounds and delegates cryptographic point/scalar
validation to the primitive modules. Unknown protobuf fields are ignored for
forward compatibility; repeated scalar fields use the last occurrence, like
protobuf. It is not a canonical-protobuf validator. Signature verification is
over the original bulletin bytes inside transaction parameters, never over a
re-encoded object. Range proofs by themselves do not enforce question counts
or sum linkage; protocol._ballot performs those checks. State diffs/acceptance
markers are NOT part of this request signature: independently authenticate
chain execution before treating these exported fields as authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------- protobuf ---

def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if pos >= len(buf) or shift >= 64:
            raise ValueError("truncated or oversized protobuf varint")
        byte = buf[pos]
        pos += 1
        if shift == 63 and byte > 1:  # The tenth byte has only one uint64 bit.
            raise ValueError("oversized protobuf varint")
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _fields(buf: bytes):
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        field, wire = key >> 3, key & 7
        if field == 0:
            raise ValueError("protobuf field number zero")
        if wire == 2:
            length, pos = _varint(buf, pos)
            if length > len(buf) - pos:
                raise ValueError("truncated protobuf field")
            yield field, buf[pos:pos + length]
            pos += length
        elif wire == 0:
            value, pos = _varint(buf, pos)
            yield field, value
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")


@dataclass
class RangeProof:
    A: bytes
    B: bytes
    As: list[bytes]
    Bs: list[bytes]
    c: list[bytes]
    r: list[bytes]


@dataclass
class Question:
    options: list[RangeProof]
    sum: RangeProof | None


def _range_proof(buf: bytes) -> RangeProof:
    proof = RangeProof(b"", b"", [], [], [], [])
    for field, value in _fields(buf):
        if field == 1:
            proof.A = value
        elif field == 2:
            proof.B = value
        elif field == 3:
            proof.As.append(value)
        elif field == 4:
            proof.Bs.append(value)
        elif field == 5:
            proof.c.append(value)
        elif field == 6:
            proof.r.append(value)
    return proof


def decode_bulletin(buf: bytes) -> list[Question]:
    questions = []
    for field, value in _fields(buf):
        if field != 1:
            continue
        options: list[RangeProof] = []
        total = None
        for qfield, qvalue in _fields(value):
            if qfield == 1:
                options.append(_range_proof(qvalue))
            elif qfield == 2:
                total = _range_proof(qvalue)
        questions.append(Question(options, total))
    return questions


# ------------------------------------------------------- transaction bytes ---

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(text: str) -> bytes:
    number = 0
    for char in text:
        number = number * 58 + B58.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


DATA_TYPE = {"integer": 0, "boolean": 1, "binary": 2, "string": 3}


def _utf8(value, name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value.encode()


def _entry_bytes(entry: dict) -> bytes:
    key = _utf8(entry["key"], "entry key")
    if "intValue" in entry:
        value = bytes([DATA_TYPE["integer"]]) + int(entry["intValue"]).to_bytes(8, "big")
    elif "boolValue" in entry:
        value = bytes([DATA_TYPE["boolean"], 1 if entry["boolValue"] else 0])
    elif "binaryValue" in entry:
        raw = _b64(entry["binaryValue"])
        value = bytes([DATA_TYPE["binary"]]) + len(raw).to_bytes(4, "big") + raw
    elif "stringValue" in entry:
        raw = _utf8(entry["stringValue"], "stringValue")
        value = bytes([DATA_TYPE["string"]]) + len(raw).to_bytes(4, "big") + raw
    else:
        raise ValueError(f"data entry without a value: {entry}")
    return bytes([0, len(key)]) + key + value


def _b64(text: str) -> bytes:
    import base64
    return base64.b64decode(text, validate=True)


def transaction_bytes(inner: dict) -> bytes:
    """The byte string a voter signs with S.Sign (chain format, not in the PDF)."""
    tx_type = inner["type"]
    version = inner["version"]
    sender = b58decode(inner["senderPublicKey"])
    params = inner["params"]
    body = len(params).to_bytes(2, "big") + b"".join(_entry_bytes(entry) for entry in params)
    timestamp = int(inner["ts"]).to_bytes(8, "big")[2:]        # the chain drops 2 bytes
    # This export serializer supports only the chain's zero-fee convention.
    if int(inner.get("fee", 0)) != 0:
        raise ValueError("nonzero transaction fee is unsupported")
    fee = (0).to_bytes(8, "big")
    asset = _utf8(inner.get("feeAssetId", ""), "feeAssetId") or b"\x00"
    out = bytearray([tx_type, version])
    out += sender
    if tx_type == 104:
        contract = b58decode(inner["contractId"])
        out += bytes([0, len(contract)]) + contract
        out += body
        out += bytes([0, 0]) + fee + timestamp
        out += int(inner["extra"]["contractVersion"]).to_bytes(4, "big")
        if version >= 3:
            out += asset
        if version >= 4:
            out += b"\x00"
    elif tx_type == 103:
        for name in ("image", "imageHash", "contractName"):
            raw = _utf8(inner["extra"][name], name)
            out += bytes([0, len(raw)]) + raw
        out += body + bytes([0, 0]) + fee + timestamp
        if version >= 2:
            out += asset
        if version >= 3:
            out += b"\x00"
        if version >= 4:
            out += bytes([0]) + (1).to_bytes(2, "big") + (2).to_bytes(2, "big")
    else:
        raise ValueError(f"unsupported transaction type {tx_type}")
    return bytes(out)
