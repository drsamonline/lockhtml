"""age v1 interoperability.

Implements the ``age`` file format (https://age-encryption.org/v1) so LockHTML
can read and write ordinary age files, interoperating with the reference
implementation.

Supported here:

* the ``X25519`` native recipient type (Bech32 ``age1…`` recipients and
  ``AGE-SECRET-KEY-1…`` identities)
* the v1 header, its MAC, and the STREAM payload (64 KiB ChaCha20-Poly1305 chunks)

Deliberately **not** implemented: the ``scrypt`` passphrase type, the hybrid
ML-KEM types, the tagged P-256 types, and ASCII armor. Unknown stanzas are
skipped on decrypt, as the spec requires, so a file that also carries a type we
do not support still opens if one of its X25519 stanzas matches.

This module is Python-only: browsers have no ChaCha20-Poly1305 in Web Crypto, so
age files cannot be opened by the HTML viewer.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION_LINE = b"age-encryption.org/v1"
X25519_INFO = b"age-encryption.org/v1/X25519"
CHUNK_SIZE = 64 * 1024
SECRET_KEY_HRP = "age-secret-key-"
RECIPIENT_HRP = "age"


# --------------------------------------------------------------------------- #
# base64 (unpadded, canonical) and Bech32
# --------------------------------------------------------------------------- #

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def b64_decode(text: str) -> bytes:
    if "=" in text:
        raise ValueError("age uses unpadded base64")
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: List[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generator[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits: int, tobits: int, pad: bool) -> Optional[List[int]]:
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, data: bytes) -> str:
    values = _convertbits(data, 8, 5, True)
    if values is None:
        raise ValueError("could not convert to bech32")
    combined = values + [0, 0, 0, 0, 0, 0]
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + combined) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in values + checksum)


def bech32_decode(text: str) -> Tuple[str, bytes]:
    if text.lower() != text and text.upper() != text:
        raise ValueError("bech32 must not be mixed case")
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        raise ValueError("malformed bech32 string")
    hrp, rest = text[:pos], text[pos + 1:]
    try:
        values = [_CHARSET.index(c) for c in rest]
    except ValueError:
        raise ValueError("invalid bech32 character")
    if _bech32_polymod(_bech32_hrp_expand(hrp) + values) != 1:
        raise ValueError("bad bech32 checksum")
    data = _convertbits(values[:-6], 5, 8, False)
    if data is None:
        raise ValueError("invalid bech32 payload")
    return hrp, bytes(data)


# --------------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------------- #

def generate_identity() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def identity_raw(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def recipient_raw(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def encode_identity(key: X25519PrivateKey) -> str:
    return bech32_encode(SECRET_KEY_HRP, identity_raw(key)).upper()


def encode_recipient(key: X25519PrivateKey) -> str:
    return bech32_encode(RECIPIENT_HRP, recipient_raw(key))


def parse_identity(text: str) -> X25519PrivateKey:
    text = text.strip()
    hrp, data = bech32_decode(text)
    if hrp != SECRET_KEY_HRP:
        raise ValueError(f"not an age identity (expected {SECRET_KEY_HRP!r})")
    if len(data) != 32:
        raise ValueError("an age identity must be 32 bytes")
    return X25519PrivateKey.from_private_bytes(data)


def parse_recipient(text: str) -> bytes:
    text = text.strip()
    hrp, data = bech32_decode(text)
    if hrp != RECIPIENT_HRP:
        raise ValueError("not an age recipient (expected the 'age' prefix)")
    if len(data) != 32:
        raise ValueError("an age recipient must be 32 bytes")
    return data


def read_identity_file(path: str) -> List[X25519PrivateKey]:
    """Read identities from an age key file (``AGE-SECRET-KEY-…`` lines)."""
    out: List[X25519PrivateKey] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.upper().startswith("AGE-SECRET-KEY-"):
                out.append(parse_identity(line))
    if not out:
        raise ValueError("no AGE-SECRET-KEY-… identities found in that file")
    return out


# --------------------------------------------------------------------------- #
# HKDF + STREAM
# --------------------------------------------------------------------------- #

def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _stream_nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def stream_encrypt(key: bytes, data: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    if not data:
        return aead.encrypt(_stream_nonce(0, True), b"", None)
    out = bytearray()
    for index, offset in enumerate(range(0, len(data), CHUNK_SIZE)):
        chunk = data[offset:offset + CHUNK_SIZE]
        out += aead.encrypt(_stream_nonce(index, offset + CHUNK_SIZE >= len(data)), chunk, None)
    return bytes(out)


def stream_decrypt(key: bytes, blob: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    out = bytearray()
    index = 0
    offset = 0
    while True:
        remaining = len(blob) - offset
        if remaining < 16:
            raise ValueError("truncated age payload")
        # Only the final chunk may be short, and it is final whenever what is
        # left fits in one chunk — including when the plaintext is an exact
        # multiple of 64 KiB, where the last chunk is full-sized but still final.
        if remaining <= CHUNK_SIZE + 16:
            out += aead.decrypt(_stream_nonce(index, True), blob[offset:], None)
            return bytes(out)
        out += aead.decrypt(
            _stream_nonce(index, False), blob[offset:offset + CHUNK_SIZE + 16], None)
        offset += CHUNK_SIZE + 16
        index += 1


# --------------------------------------------------------------------------- #
# header
# --------------------------------------------------------------------------- #

def _wrap(body: str) -> bytes:
    """Wrap a base64 body at 64 columns, ending with a short (possibly empty) line."""
    lines = [body[i:i + 64] for i in range(0, len(body), 64)] or [""]
    if len(body) % 64 == 0 and body:
        lines.append("")
    return "".join(line + "\n" for line in lines).encode("ascii")


def _header_mac(file_key: bytes, header_without_mac: bytes) -> bytes:
    mac_key = _hkdf(file_key, b"", b"header")
    return hmac.new(mac_key, header_without_mac, hashlib.sha256).digest()


def _x25519_stanza(recipient: bytes, file_key: bytes) -> Tuple[str, bytes]:
    ephemeral = X25519PrivateKey.generate()
    ephemeral_share = recipient_raw(ephemeral)
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient))
    wrap_key = _hkdf(shared, ephemeral_share + recipient, X25519_INFO)
    body = ChaCha20Poly1305(wrap_key).encrypt(b"\x00" * 12, file_key, None)
    return b64_encode(ephemeral_share), body


def encrypt(data: bytes, recipients: List[bytes]) -> bytes:
    """Encrypt ``data`` to one or more raw X25519 recipients."""
    if not recipients:
        raise ValueError("age needs at least one recipient")
    file_key = os.urandom(16)

    header = VERSION_LINE + b"\n"
    for recipient in recipients:
        share, body = _x25519_stanza(recipient, file_key)
        header += b"-> X25519 " + share.encode("ascii") + b"\n"
        header += _wrap(b64_encode(body))

    header += b"---"
    mac = _header_mac(file_key, header)
    header += b" " + b64_encode(mac).encode("ascii") + b"\n"

    nonce = os.urandom(16)
    payload_key = _hkdf(file_key, nonce, b"payload")
    return header + nonce + stream_encrypt(payload_key, data)


def _parse_header(data: bytes) -> Tuple[List[Tuple[List[str], bytes]], bytes, bytes]:
    """Return ``(stanzas, mac_input, rest)`` where ``mac_input`` ends at ``---``."""
    if not data.startswith(VERSION_LINE + b"\n"):
        raise ValueError("not an age v1 file")
    pos = len(VERSION_LINE) + 1
    stanzas: List[Tuple[List[str], bytes]] = []

    while True:
        end = data.find(b"\n", pos)
        if end == -1:
            raise ValueError("truncated age header")
        line = data[pos:end]

        if line.startswith(b"---"):
            if not line.startswith(b"--- "):
                raise ValueError("malformed age header MAC line")
            mac_input = data[:pos] + b"---"
            mac = b64_decode(line[4:].decode("ascii"))
            rest = data[end + 1:]
            return stanzas, mac_input, (mac, rest)

        if not line.startswith(b"-> "):
            raise ValueError("unexpected line in age header")
        args = line[3:].decode("ascii").split(" ")
        pos = end + 1
        body_b64 = ""
        while True:
            end = data.find(b"\n", pos)
            if end == -1:
                raise ValueError("truncated age stanza")
            chunk = data[pos:end].decode("ascii")
            pos = end + 1
            body_b64 += chunk
            if len(chunk) < 64:
                break
        stanzas.append((args, b64_decode(body_b64)))


def _unwrap_file_key(stanzas, identities: List[X25519PrivateKey]) -> bytes:
    for args, body in stanzas:
        if not args or args[0] != "X25519" or len(args) != 2:
            continue                      # unknown stanza type: skip, per spec
        if len(body) != 32:
            continue                      # mitigate partitioning oracles
        share = b64_decode(args[1])
        if len(share) != 32:
            continue
        ephemeral = X25519PublicKey.from_public_bytes(share)
        for identity in identities:
            shared = identity.exchange(ephemeral)
            if shared == b"\x00" * 32:
                raise ValueError("refusing a low-order age recipient share")
            wrap_key = _hkdf(shared, share + recipient_raw(identity), X25519_INFO)
            try:
                return ChaCha20Poly1305(wrap_key).decrypt(b"\x00" * 12, body, None)
            except Exception:
                continue
    raise ValueError("no identity matched any of the recipients")


def decrypt(data: bytes, identities: List[X25519PrivateKey]) -> bytes:
    """Decrypt an age v1 file with one of ``identities``."""
    if not identities:
        raise ValueError("age needs at least one identity")
    stanzas, mac_input, (mac, rest) = _parse_header(data)
    file_key = _unwrap_file_key(stanzas, identities)
    if not hmac.compare_digest(_header_mac(file_key, mac_input), mac):
        raise ValueError("age header MAC does not verify")
    if len(rest) < 16:
        raise ValueError("truncated age payload")
    nonce, body = rest[:16], rest[16:]
    payload_key = _hkdf(file_key, nonce, b"payload")
    return stream_decrypt(payload_key, body)
