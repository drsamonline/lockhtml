"""Cryptographic core for LockHTML (format v2).

A locked file is an ordinary HTML page (the *viewer*) with a JSON *payload*
embedded in a ``<script id="payload" type="application/json">`` tag. The
original document never appears in plaintext.

Payload schema (v2)
-------------------
{
  "v":          2,
  "kind":       "html" | "file",      # what the plaintext is
  "name":       "report.html" | null, # original filename (kind == "file")
  "kdf":        "argon2id" | "pbkdf2",
  "kdfparams":  {"m":19456,"t":2,"p":1}  # argon2id
                | {"iter":250000},        # pbkdf2
  "salt":       "<base64>",           # 16 random bytes
  "iv":         "<base64>",           # 12 random bytes (AES-GCM nonce)
  "ct":         "<base64>",           # AES-256-GCM ciphertext + tag
  "id":         "<hex>",              # short id of the ciphertext
  "onetime":    true | false,         # legacy shorthand for maxviews == 1
  "maxviews":   1 | null,             # view limit, null = unlimited
  "notbefore":  "ISO8601" | null,     # refuse to open before this time
  "expires":    "ISO8601" | null,     # refuse to open after this time
  "watermark":  "text" | null,        # overlay shown on the decrypted view
  "keyfile":    true | false,         # a keyfile is required in addition to PIN
  "sig":        {"alg":"Ed25519","pub":"<b64>","val":"<b64>"} | null,
  "decoy":      {salt,iv,ct,kdf,kdfparams} | null   # opens with the duress PIN
}

Key derivation input
--------------------
* ``pbkdf2``  : password bytes = utf8(pin) || keyfile_bytes
* ``argon2id``: password = utf8(pin); keyfile_bytes passed as Argon2 ``secret``

Legacy v1 payloads (``kdf == "PBKDF2-SHA256"`` with a top-level ``iter``) are
still readable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import time
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Dict, List, Optional, Tuple, Union

from argon2.low_level import Type as _Argon2Type
from argon2.low_level import hash_secret_raw as _argon2_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FORMAT_VERSION = 2

#: Default KDF and its parameters.
DEFAULT_KDF = "argon2id"
#: Argon2id parameters (m in KiB). 19 MiB is the OWASP-recommended floor.
ARGON2_PARAMS = {"m": 19456, "t": 2, "p": 1}
#: PBKDF2 parameters used when the argon2id WASM is unavailable.
PBKDF2_PARAMS = {"iter": 250_000}

PAYLOAD_PLACEHOLDER = "__PAYLOAD__"
_PAYLOAD_RE = re.compile(
    r'<script id="payload" type="application/json">(.*?)</script>', re.DOTALL
)

Source = Union[str, bytes]
Decoy = Tuple[Source, str]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data)


def _as_bytes(data: Source) -> bytes:
    return data.encode("utf-8") if isinstance(data, str) else data


def _iso(value: Optional[Union[str, datetime]]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


# --------------------------------------------------------------------------- #
# key derivation
# --------------------------------------------------------------------------- #
def derive_key(
    pin: str,
    salt: bytes,
    kdf: str = DEFAULT_KDF,
    kdfparams: Optional[Dict[str, Any]] = None,
    keyfile: Optional[bytes] = None,
) -> bytes:
    """Derive a 256-bit AES key from ``pin`` (+ optional keyfile)."""
    kdfparams = dict(kdfparams or {})
    pin_bytes = pin.encode("utf-8")

    if kdf in ("argon2id", "argon2"):
        params = kdfparams or ARGON2_PARAMS
        raw = _argon2_raw(
            secret=pin_bytes,
            salt=salt,
            time_cost=int(params.get("t", 2)),
            memory_cost=int(params.get("m", 19456)),
            parallelism=int(params.get("p", 1)),
            hash_len=32,
            type=_Argon2Type.ID,
        )
    elif kdf in ("pbkdf2", "PBKDF2-SHA256"):
        # legacy v1 stored the iteration count at the top level
        iterations = int(kdfparams.get("iter", PBKDF2_PARAMS["iter"]))
        raw = hashlib.pbkdf2_hmac("sha256", pin_bytes, salt, iterations, dklen=32)
    else:
        raise ValueError(f"unknown kdf: {kdf!r}")

    # Optional keyfile: mix it in as a pepper (post-KDF HMAC), so the file
    # cannot be opened with the PIN alone. Identical in the JS implementations.
    if keyfile:
        raw = hmac.new(raw, keyfile, hashlib.sha256).digest()
    return raw


# --------------------------------------------------------------------------- #
# auto-calibrated KDF cost
# --------------------------------------------------------------------------- #
# Argon2id is memory-hard, but a fixed time cost is wrong on both a phone and a
# workstation. ``calibrate_argon2`` times one pass on this machine and scales the
# time cost so a single derivation takes about ``target_seconds``.

DEFAULT_KDF_SECONDS = 0.5


def calibrate_argon2(
    target_seconds: float = DEFAULT_KDF_SECONDS,
    memory_kib: int = ARGON2_PARAMS["m"],
    parallelism: int = ARGON2_PARAMS["p"],
) -> Dict[str, int]:
    """Measure this machine and return argon2id params for ~``target_seconds``."""
    salt, secret = b"\x00" * 16, b"\x01" * 16
    started = time.perf_counter()
    _argon2_raw(secret, salt, time_cost=1, memory_cost=memory_kib,
                parallelism=parallelism, hash_len=32, type=_Argon2Type.ID)
    elapsed = max(time.perf_counter() - started, 1e-4)
    time_cost = int(round(target_seconds / elapsed))
    return {"m": int(memory_kib), "t": max(1, min(64, time_cost)), "p": int(parallelism)}


# --------------------------------------------------------------------------- #
# Ed25519 signing
# --------------------------------------------------------------------------- #

def generate_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def save_signing_key(key: Ed25519PrivateKey, path: str) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as fh:
        fh.write(pem)


def load_signing_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def public_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _sign_ciphertext(key: Ed25519PrivateKey, ciphertext: bytes) -> Dict[str, str]:
    return {
        "alg": "Ed25519",
        "pub": _b64(public_key_bytes(key)),
        "val": _b64(key.sign(ciphertext)),
    }


def verify_signature(payload: Dict[str, Any]) -> Optional[bool]:
    """Return True/False if a signature is present and checkable, else None."""
    sig = payload.get("sig")
    if not sig:
        return None
    try:
        pub = Ed25519PublicKey.from_public_bytes(_unb64(sig["pub"]))
        pub.verify(_unb64(sig["val"]), _unb64(payload["ct"]))
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# encrypt / decrypt
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# X25519 recipient mode (lock to a public key)
# --------------------------------------------------------------------------- #
# Hybrid encryption: a fresh ephemeral X25519 keypair is generated per file, its
# shared secret with the recipient's public key becomes HKDF input keying
# material, and the resulting 32-byte key encrypts the payload with AES-GCM. An
# optional PIN (and the optional keyfile pepper) can be layered on top.
#
#   shared = X25519(ephemeral_private, recipient_public)
#          = X25519(recipient_private, ephemeral_public)
#   ikm    = shared || utf8(pin)              (pin only when required)
#   key    = HKDF-SHA256(ikm, salt, info="lockhtml/x25519", 32)
#   key    = HMAC-SHA256(key, keyfile)        (only when a keyfile is required)

HKDF_INFO = b"lockhtml/x25519"


def generate_recipient_key() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def recipient_public_bytes(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def save_recipient_key(key: X25519PrivateKey, path: str) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with open(path, "wb") as fh:
        fh.write(pem)


def load_recipient_key(path: str) -> X25519PrivateKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, X25519PrivateKey):
        raise ValueError("not an X25519 private key")
    return key


def parse_recipient_public(value: Union[str, bytes]) -> bytes:
    """Accept a base64 key, a .pub file's contents, or a PEM public key."""
    text = value.decode("utf-8", "ignore") if isinstance(value, (bytes, bytearray)) else value
    text = text.strip()
    if "BEGIN PUBLIC KEY" in text:
        pub = serialization.load_pem_public_key(text.encode("utf-8"))
        if not isinstance(pub, X25519PublicKey):
            raise ValueError("not an X25519 public key")
        return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    raw = base64.b64decode("".join(text.split()))
    if len(raw) != 32:
        raise ValueError("an X25519 public key must be 32 bytes")
    return raw


def _recipient_key(shared: bytes, pin: Optional[str], keyfile: Optional[bytes],
                   salt: bytes) -> bytes:
    ikm = shared + (pin.encode("utf-8") if pin else b"")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO).derive(ikm)
    if keyfile:
        key = hmac.new(key, keyfile, hashlib.sha256).digest()
    return key


# --------------------------------------------------------------------------- #
# Shamir secret sharing (split the key between several holders)
# --------------------------------------------------------------------------- #
# The 32-byte key seed is split into n shares with threshold k using Shamir's
# scheme over GF(256). Any k shares reconstruct the seed; k-1 reveal nothing.
# A share is encoded as base64(bytes([x]) + y), where x is the share index.

SHAMIR_INFO = b"lockhtml/shamir"


def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_pow(a: int, e: int) -> int:
    r = 1
    while e:
        if e & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        e >>= 1
    return r


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("no inverse for 0 in GF(256)")
    return _gf_pow(a, 254)


def shamir_split(secret: bytes, n: int, k: int, rng=None) -> List[bytes]:
    """Split ``secret`` into ``n`` shares, any ``k`` of which reconstruct it."""
    if not (1 <= k <= n <= 255):
        raise ValueError("need 1 <= k <= n <= 255")
    rng = rng or os.urandom
    shares = [bytearray([x]) for x in range(1, n + 1)]
    for byte in secret:
        coeffs = [byte] + list(rng(k - 1))
        for i, x in enumerate(range(1, n + 1)):
            y = 0
            for c in reversed(coeffs):
                y = _gf_mul(y, x) ^ c
            shares[i].append(y)
    return [bytes(s) for s in shares]


def shamir_combine(shares: List[bytes]) -> bytes:
    """Reconstruct the secret from shares produced by :func:`shamir_split`."""
    if not shares:
        raise ValueError("no shares given")
    length = len(shares[0]) - 1
    if any(len(s) != length + 1 for s in shares):
        raise ValueError("shares have inconsistent lengths")
    xs = [s[0] for s in shares]
    if 0 in xs:
        raise ValueError("invalid share index 0")
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share index")
    secret = bytearray(length)
    for j in range(length):
        acc = 0
        for i, si in enumerate(shares):
            num = den = 1
            for m, sm in enumerate(shares):
                if m == i:
                    continue
                num = _gf_mul(num, xs[m])
                den = _gf_mul(den, xs[i] ^ xs[m])
            acc ^= _gf_mul(si[1 + j], _gf_mul(num, _gf_inv(den)))
        secret[j] = acc
    return bytes(secret)


def _shares_key(seed: bytes, pin: Optional[str], keyfile: Optional[bytes], salt: bytes) -> bytes:
    ikm = seed + (pin.encode("utf-8") if pin else b"")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=SHAMIR_INFO).derive(ikm)
    if keyfile:
        key = hmac.new(key, keyfile, hashlib.sha256).digest()
    return key


def encrypt_shares(
    data: Source,
    pin: Optional[str] = None,
    *,
    n: int,
    k: int,
    keyfile: Optional[bytes] = None,
    one_time: bool = False,
    max_views: Optional[int] = None,
    not_before: Optional[Union[str, datetime]] = None,
    expires: Optional[Union[str, datetime]] = None,
    watermark: Optional[str] = None,
    kind: str = "html",
    name: Optional[str] = None,
    sign_key: Optional[Ed25519PrivateKey] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """Encrypt ``data`` and split its key; returns ``(payload, share_strings)``."""
    if not (1 <= k <= n <= 255):
        raise ValueError("need 1 <= k <= n <= 255")
    seed = os.urandom(32)
    salt, iv = os.urandom(16), os.urandom(12)
    key = _shares_key(seed, pin, keyfile, salt)
    ct = AESGCM(key).encrypt(iv, _as_bytes(data), None)

    if one_time and max_views is None:
        max_views = 1

    payload: Dict[str, Any] = {
        "v": FORMAT_VERSION,
        "kind": kind,
        "name": name,
        "mode": "shares",
        "kdf": "shamir-hkdf",
        "kdfparams": {"info": SHAMIR_INFO.decode("ascii"), "n": n, "k": k},
        "eph": None,
        "pin": bool(pin),
        "salt": _b64(salt),
        "iv": _b64(iv),
        "ct": _b64(ct),
        "id": hashlib.sha256(ct).hexdigest()[:16],
        "onetime": bool(one_time or max_views == 1),
        "maxviews": max_views,
        "notbefore": _iso(not_before),
        "expires": _iso(expires),
        "watermark": watermark,
        "keyfile": bool(keyfile),
        "sig": _sign_ciphertext(sign_key, ct) if sign_key else None,
        "decoy": None,
    }
    return payload, [_b64(s) for s in shamir_split(seed, n, k)]


def build_shared_html(source: Source, pin: Optional[str] = None, *, n: int, k: int,
                      template: Optional[str] = None, **kwargs: Any
                      ) -> Tuple[str, List[str]]:
    """Like :func:`build_locked_html`, but returns the share strings too."""
    payload, shares = encrypt_shares(source, pin, n=n, k=k, **kwargs)
    tpl = template if template is not None else load_template(payload["kdf"])
    if PAYLOAD_PLACEHOLDER not in tpl:
        raise ValueError("viewer template is missing the __PAYLOAD__ placeholder")
    html = tpl.replace(PAYLOAD_PLACEHOLDER, json.dumps(payload, separators=(",", ":")))
    return html, shares


def _encrypt_blob(
    data: bytes,
    pin: str,
    kdf: str,
    kdfparams: Dict[str, Any],
    keyfile: Optional[bytes],
) -> Dict[str, Any]:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(pin, salt, kdf, kdfparams, keyfile)
    ct = AESGCM(key).encrypt(iv, data, None)
    return {"salt": _b64(salt), "iv": _b64(iv), "ct": _b64(ct)}


def encrypt(
    data: Source,
    pin: Optional[str] = None,
    *,
    recipient: Optional[bytes] = None,
    kdf: str = DEFAULT_KDF,
    kdfparams: Optional[Dict[str, Any]] = None,
    keyfile: Optional[bytes] = None,
    one_time: bool = False,
    max_views: Optional[int] = None,
    not_before: Optional[Union[str, datetime]] = None,
    expires: Optional[Union[str, datetime]] = None,
    watermark: Optional[str] = None,
    kind: str = "html",
    name: Optional[str] = None,
    sign_key: Optional[Ed25519PrivateKey] = None,
    decoy: Optional[Decoy] = None,
    hidden: Optional[List[Tuple[str, Source]]] = None,
) -> Dict[str, Any]:
    """Encrypt ``data`` under a PIN, or to a recipient's X25519 public key."""
    if recipient is not None and (decoy is not None or hidden):
        raise ValueError("extra PIN slots are only available in PIN mode")

    if recipient is not None:
        eph = X25519PrivateKey.generate()
        shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient))
        salt, iv = os.urandom(16), os.urandom(12)
        key = _recipient_key(shared, pin, keyfile, salt)
        ct = AESGCM(key).encrypt(iv, _as_bytes(data), None)
        blob = {"salt": _b64(salt), "iv": _b64(iv), "ct": _b64(ct)}
        mode_fields: Dict[str, Any] = {
            "mode": "recipient",
            "kdf": "x25519-hkdf",
            "kdfparams": {"info": HKDF_INFO.decode("ascii")},
            "eph": _b64(recipient_public_bytes(eph)),
            "pin": bool(pin),
        }
    else:
        if pin is None:
            raise ValueError("a PIN or a recipient public key is required")
        if kdfparams is None:
            kdfparams = ARGON2_PARAMS if kdf == "argon2id" else PBKDF2_PARAMS
        blob = _encrypt_blob(_as_bytes(data), pin, kdf, kdfparams, keyfile)
        mode_fields = {"mode": "pin", "kdf": kdf, "kdfparams": dict(kdfparams),
                       "eph": None, "pin": True}

    ciphertext = _unb64(blob["ct"])

    if one_time and max_views is None:
        max_views = 1

    payload: Dict[str, Any] = {
        "v": FORMAT_VERSION,
        "kind": kind,
        "name": name,
        **mode_fields,
        "salt": blob["salt"],
        "iv": blob["iv"],
        "ct": blob["ct"],
        "id": hashlib.sha256(ciphertext).hexdigest()[:16],
        "onetime": bool(one_time or max_views == 1),
        "maxviews": max_views,
        "notbefore": _iso(not_before),
        "expires": _iso(expires),
        "watermark": watermark,
        "keyfile": bool(keyfile),
        "sig": _sign_ciphertext(sign_key, ciphertext) if sign_key else None,
        "decoy": None,
    }

    if decoy is not None:
        decoy_data, decoy_pin = decoy
        d = _encrypt_blob(_as_bytes(decoy_data), decoy_pin, kdf, kdfparams, keyfile)
        payload["decoy"] = {
            "kdf": kdf, "kdfparams": dict(kdfparams),
            "salt": d["salt"], "iv": d["iv"], "ct": d["ct"],
        }

    if hidden:
        slots = []
        for hidden_pin, hidden_data in hidden:
            s = _encrypt_blob(_as_bytes(hidden_data), hidden_pin, kdf, kdfparams, keyfile)
            slots.append({
                "kdf": kdf, "kdfparams": dict(kdfparams),
                "salt": s["salt"], "iv": s["iv"], "ct": s["ct"],
            })
        payload["slots"] = slots

    return payload


def _decrypt_blob(blob: Dict[str, Any], pin: Optional[str], keyfile: Optional[bytes],
                  private_key: Optional[X25519PrivateKey] = None,
                  shares: Optional[List[str]] = None) -> bytes:
    if "ct" not in blob or "iv" not in blob:
        # A streaming payload keeps its ciphertext in the sidecar, not the HTML.
        raise ValueError("not an embedded payload; streaming containers need their sidecar")
    mode = blob.get("mode")
    if mode == "recipient":
        if private_key is None:
            raise ValueError("this file needs its X25519 private key")
        shared = private_key.exchange(
            X25519PublicKey.from_public_bytes(_unb64(blob["eph"])))
        key = _recipient_key(shared, pin if blob.get("pin") else None, keyfile,
                             _unb64(blob["salt"]))
    elif mode == "shares":
        if not shares:
            raise ValueError("this file needs its key shares")
        k = int((blob.get("kdfparams") or {}).get("k") or len(shares))
        raw = [_unb64(s) for s in shares]
        if len(raw) < k:
            raise ValueError("not enough shares")
        seed = shamir_combine(raw[:k])
        key = _shares_key(seed, pin if blob.get("pin") else None, keyfile,
                          _unb64(blob["salt"]))
    else:
        if pin is None:
            raise ValueError("a PIN is required")
        kdf = blob.get("kdf", DEFAULT_KDF)
        kdfparams = blob.get("kdfparams")
        if kdfparams is None and "iter" in blob:  # legacy v1
            kdfparams = {"iter": blob["iter"]}
        key = derive_key(pin, _unb64(blob["salt"]), kdf, kdfparams, keyfile)
    return AESGCM(key).decrypt(_unb64(blob["iv"]), _unb64(blob["ct"]), None)


def decrypt(payload: Dict[str, Any], pin: Optional[str] = None,
            keyfile: Optional[bytes] = None,
            private_key: Optional[X25519PrivateKey] = None,
            shares: Optional[List[str]] = None) -> bytes:
    """Decrypt a payload with a PIN, an X25519 private key, or key shares."""
    return _decrypt_blob(payload, pin, keyfile, private_key, shares)


def try_decoy(payload: Dict[str, Any], pin: str, keyfile: Optional[bytes] = None):
    """Return the decoy plaintext if ``pin`` opens it, else None."""
    decoy = payload.get("decoy")
    if not decoy:
        return None
    try:
        return _decrypt_blob(decoy, pin, keyfile)
    except Exception:
        return None


def decrypt_any(payload: Dict[str, Any], pin: str, keyfile: Optional[bytes] = None
                ) -> Tuple[bytes, str]:
    """Try the main payload, then every hidden slot, then the decoy.

    Returns ``(plaintext, which)`` where ``which`` is ``"main"``, ``"slot<n>"`` or
    ``"decoy"``. Raises ``ValueError`` if the PIN opens nothing.
    """
    for name, blob in _all_blobs(payload):
        try:
            return _decrypt_blob(blob, pin, keyfile), name
        except Exception:
            continue
    raise ValueError("wrong PIN")


def _all_blobs(payload: Dict[str, Any]):
    """Yield ``(name, blob)`` for the main payload, hidden slots and the decoy."""
    yield "main", payload
    for i, slot in enumerate(payload.get("slots") or []):
        yield f"slot{i}", slot
    if payload.get("decoy"):
        yield "decoy", payload["decoy"]


# --------------------------------------------------------------------------- #
# locked-file assembly
# --------------------------------------------------------------------------- #
def load_template(kdf: str = DEFAULT_KDF) -> str:
    """Return the viewer template for ``kdf`` (argon2-aware or lightweight)."""
    name = "viewer-argon2.html" if kdf in ("argon2id", "argon2") else "viewer.html"
    return (
        resources.files("lockhtml")
        .joinpath("templates/" + name)
        .read_text(encoding="utf-8")
    )


def build_locked_html(
    source: Source,
    pin: Optional[str] = None,
    *,
    template: Optional[str] = None,
    **kwargs: Any,
) -> str:
    """Encrypt ``source`` and return the complete locked HTML document."""
    payload = encrypt(source, pin, **kwargs)
    tpl = template if template is not None else load_template(payload["kdf"])
    if PAYLOAD_PLACEHOLDER not in tpl:
        raise ValueError("viewer template is missing the __PAYLOAD__ placeholder")
    return tpl.replace(PAYLOAD_PLACEHOLDER, json.dumps(payload, separators=(",", ":")))


def extract_payload(locked_html: str) -> Dict[str, Any]:
    match = _PAYLOAD_RE.search(locked_html)
    if not match:
        raise ValueError("no LockHTML payload found in this file")
    return json.loads(match.group(1))


def unlock(locked_html: str, pin: Optional[str] = None,
           keyfile: Optional[bytes] = None,
           private_key: Optional[X25519PrivateKey] = None,
           shares: Optional[List[str]] = None) -> bytes:
    """Decrypt a locked HTML document back to its original plaintext bytes.

    In PIN mode this also opens hidden slots and the duress decoy, whichever the
    PIN unlocks first (main payload, then slots, then decoy).
    """
    payload = extract_payload(locked_html)
    if payload.get("container") == "stream":
        raise ValueError(
            "this is a streaming container; call stream_decrypt_file() with its .bin sidecar")
    if payload.get("mode") in (None, "pin"):
        if pin is None:
            raise ValueError("a PIN is required")
        return decrypt_any(payload, pin, keyfile)[0]
    return decrypt(payload, pin, keyfile, private_key, shares)


# --------------------------------------------------------------------------- #
# Streaming container (for large files)
# --------------------------------------------------------------------------- #
#
# The embedded format holds the whole ciphertext inside the HTML as base64, so
# memory use is roughly 3-4x the file size and the browser's string limits cap
# it at a few hundred MB. The streaming container instead writes the ciphertext
# to a sidecar file, encrypted in fixed-size chunks, so both sides can work at
# ~O(chunk size) memory.
#
# Layout of the sidecar file (<name>.locked.bin):
#
#     MAGIC (5 bytes) || chunk_0 || chunk_1 || ... || chunk_{n-1}
#
# Each chunk is AES-256-GCM(plaintext, nonce, aad) = ciphertext || 16-byte tag,
# where, for chunk i:
#     nonce = base_iv (8 random bytes) || uint32_be(i)
#     aad   = uint32_be(i)          # binds the chunk's position
#
# Whole-file integrity is bound by a MAC over the metadata *and* every chunk tag,
# which prevents reordering, duplication, truncation and metadata tampering:
#
#     mac_input = meta_string || tag_0 || ... || tag_{n-1}
#     metamac   = HMAC-SHA256(key, mac_input)
#     signature = Ed25519(mac_input)            # optional

STREAM_MAGIC = b"LKHS1"
#: Default chunk size for the streaming container (1 MiB).
DEFAULT_CHUNK_SIZE = 1 << 20


def _kdfparams_str(kdfparams: Dict[str, Any]) -> str:
    if "m" in kdfparams:
        return f"{kdfparams['m']},{kdfparams.get('t')},{kdfparams.get('p')}"
    if "n" in kdfparams:  # shamir shares mode
        return f"{kdfparams.get('info')},{kdfparams['n']},{kdfparams['k']}"
    if "info" in kdfparams:  # x25519 recipient mode
        return str(kdfparams["info"])
    return str(kdfparams.get("iter"))


def _meta_string(payload: Dict[str, Any]) -> str:
    """Deterministic, order-fixed metadata that the integrity MAC covers."""
    parts = [
        f"v{FORMAT_VERSION}",
        str(payload.get("kdf")),
        _kdfparams_str(payload.get("kdfparams") or {}),
        str(payload.get("chunkSize")),
        str(payload.get("chunkCount")),
        str(payload.get("kind")),
        str(payload.get("name") or ""),
        str(payload.get("salt")),
        str(payload.get("baseiv")),
        "" if payload.get("maxviews") is None else str(payload.get("maxviews")),
        str(payload.get("notbefore") or ""),
        str(payload.get("expires") or ""),
    ]
    # Appended only when present, so older PIN-mode sidecars still verify.
    if payload.get("mode") == "recipient":
        parts.append(str(payload.get("eph") or ""))
    if payload.get("decoy"):
        parts.append(str(payload["decoy"].get("ct") or ""))
    return "|".join(parts)


def _chunk_nonce(base_iv: bytes, index: int) -> bytes:
    return base_iv + index.to_bytes(4, "big")


def _chunk_aad(index: int) -> bytes:
    return index.to_bytes(4, "big")


def _stream_write(
    src_path: str,
    data_path: str,
    key: bytes,
    salt: bytes,
    base_iv: bytes,
    mode_fields: Dict[str, Any],
    *,
    chunk_size: int,
    one_time: bool,
    max_views: Optional[int],
    not_before: Optional[Union[str, datetime]],
    expires: Optional[Union[str, datetime]],
    watermark: Optional[str],
    kind: str,
    name: Optional[str],
    sign_key: Optional[Ed25519PrivateKey],
    keyfile: bool,
    decoy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Chunk-encrypt ``src_path`` into ``data_path`` and return the viewer payload."""
    if one_time and max_views is None:
        max_views = 1
    aes = AESGCM(key)

    total = os.path.getsize(src_path)
    chunk_count = max(1, math.ceil(total / chunk_size))

    payload: Dict[str, Any] = {
        "v": FORMAT_VERSION,
        "container": "stream",
        "kind": kind,
        "name": name,
        **mode_fields,
        "salt": _b64(salt),
        "baseiv": _b64(base_iv),
        "chunkSize": chunk_size,
        "chunkCount": chunk_count,
        "data": os.path.basename(data_path),
        "onetime": bool(one_time or max_views == 1),
        "maxviews": max_views,
        "notbefore": _iso(not_before),
        "expires": _iso(expires),
        "watermark": watermark,
        "keyfile": bool(keyfile),
        "sig": None,
        "decoy": decoy,
        "metamac": None,
        "id": None,
    }

    meta = _meta_string(payload).encode("utf-8")
    tags = bytearray()

    with open(src_path, "rb") as fi, open(data_path, "wb") as fo:
        fo.write(STREAM_MAGIC)
        index = 0
        while True:
            chunk = fi.read(chunk_size)
            if not chunk and index > 0:
                break
            ct = aes.encrypt(_chunk_nonce(base_iv, index), chunk, _chunk_aad(index))
            fo.write(ct)
            tags += ct[-16:]
            index += 1
            if not chunk:
                break

    mac_input = bytes(meta + tags)
    payload["metamac"] = _b64(hmac.new(key, mac_input, hashlib.sha256).digest())
    payload["id"] = hashlib.sha256(mac_input).hexdigest()[:16]
    if sign_key is not None:
        payload["sig"] = {
            "alg": "Ed25519",
            "pub": _b64(public_key_bytes(sign_key)),
            "val": _b64(sign_key.sign(mac_input)),
        }
    return payload


def stream_encrypt_file(
    src_path: str,
    pin: Optional[str] = None,
    data_path: str = "",
    *,
    recipient: Optional[bytes] = None,
    kdf: str = DEFAULT_KDF,
    kdfparams: Optional[Dict[str, Any]] = None,
    keyfile: Optional[bytes] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    one_time: bool = False,
    max_views: Optional[int] = None,
    not_before: Optional[Union[str, datetime]] = None,
    expires: Optional[Union[str, datetime]] = None,
    watermark: Optional[str] = None,
    kind: str = "file",
    name: Optional[str] = None,
    sign_key: Optional[Ed25519PrivateKey] = None,
    decoy: Optional[Decoy] = None,
) -> Dict[str, Any]:
    """Encrypt a file into a streaming sidecar; returns the payload for the viewer."""
    salt = os.urandom(16)
    base_iv = os.urandom(8)
    if decoy is not None and recipient is not None:
        raise ValueError("the decoy PIN is only available in PIN mode")
    if recipient is not None:
        eph = X25519PrivateKey.generate()
        shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient))
        key = _recipient_key(shared, pin, keyfile, salt)
        mode_fields: Dict[str, Any] = {
            "mode": "recipient", "kdf": "x25519-hkdf",
            "kdfparams": {"info": HKDF_INFO.decode("ascii")},
            "eph": _b64(recipient_public_bytes(eph)), "pin": bool(pin),
        }
    else:
        if pin is None:
            raise ValueError("a PIN or a recipient public key is required")
        if kdfparams is None:
            kdfparams = ARGON2_PARAMS if kdf == "argon2id" else PBKDF2_PARAMS
        key = derive_key(pin, salt, kdf, kdfparams, keyfile)
        mode_fields = {"mode": "pin", "kdf": kdf, "kdfparams": dict(kdfparams),
                       "eph": None, "pin": True}

    decoy_blob = None
    if decoy is not None:
        decoy_data, decoy_pin = decoy
        d = _encrypt_blob(_as_bytes(decoy_data), decoy_pin, kdf, kdfparams, keyfile)
        decoy_blob = {
            "kdf": kdf, "kdfparams": dict(kdfparams),
            "salt": d["salt"], "iv": d["iv"], "ct": d["ct"],
        }

    return _stream_write(
        src_path, data_path, key, salt, base_iv, mode_fields,
        chunk_size=chunk_size, one_time=one_time, max_views=max_views,
        not_before=not_before, expires=expires, watermark=watermark,
        kind=kind, name=name, sign_key=sign_key, keyfile=bool(keyfile),
        decoy=decoy_blob)


def stream_encrypt_shares_file(
    src_path: str,
    pin: Optional[str] = None,
    data_path: str = "",
    *,
    n: int,
    k: int,
    keyfile: Optional[bytes] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    one_time: bool = False,
    max_views: Optional[int] = None,
    not_before: Optional[Union[str, datetime]] = None,
    expires: Optional[Union[str, datetime]] = None,
    watermark: Optional[str] = None,
    kind: str = "file",
    name: Optional[str] = None,
    sign_key: Optional[Ed25519PrivateKey] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """Streaming container whose key is split into ``n`` shares (any ``k`` open it)."""
    if not (1 <= k <= n <= 255):
        raise ValueError("need 1 <= k <= n <= 255")
    salt = os.urandom(16)
    base_iv = os.urandom(8)
    seed = os.urandom(32)
    key = _shares_key(seed, pin, keyfile, salt)
    mode_fields: Dict[str, Any] = {
        "mode": "shares", "kdf": "shamir-hkdf",
        "kdfparams": {"info": SHAMIR_INFO.decode("ascii"), "n": n, "k": k},
        "eph": None, "pin": bool(pin),
    }
    payload = _stream_write(
        src_path, data_path, key, salt, base_iv, mode_fields,
        chunk_size=chunk_size, one_time=one_time, max_views=max_views,
        not_before=not_before, expires=expires, watermark=watermark,
        kind=kind, name=name, sign_key=sign_key, keyfile=bool(keyfile))
    return payload, [_b64(s) for s in shamir_split(seed, n, k)]


def stream_decrypt_file(
    data_path: str,
    payload: Dict[str, Any],
    pin: Optional[str] = None,
    out_path: Optional[str] = None,
    keyfile: Optional[bytes] = None,
    private_key: Optional[X25519PrivateKey] = None,
    shares: Optional[List[str]] = None,
) -> Optional[bytes]:
    """Verify and decrypt a streaming sidecar. Returns bytes if out_path is None."""
    mode = payload.get("mode")
    if mode == "recipient":
        if private_key is None:
            raise ValueError("this file needs its X25519 private key")
        shared = private_key.exchange(
            X25519PublicKey.from_public_bytes(_unb64(payload["eph"])))
        key = _recipient_key(shared, pin if payload.get("pin") else None, keyfile,
                             _unb64(payload["salt"]))
    elif mode == "shares":
        if not shares:
            raise ValueError("this file needs its key shares")
        k = int((payload.get("kdfparams") or {}).get("k") or len(shares))
        raw = [_unb64(s) for s in shares]
        if len(raw) < k:
            raise ValueError("not enough shares")
        seed = shamir_combine(raw[:k])
        key = _shares_key(seed, pin if payload.get("pin") else None, keyfile,
                          _unb64(payload["salt"]))
    else:
        if pin is None:
            raise ValueError("a PIN is required")
        key = derive_key(pin, _unb64(payload["salt"]), payload["kdf"],
                         payload.get("kdfparams"), keyfile)
    aes = AESGCM(key)
    base_iv = _unb64(payload["baseiv"])
    chunk_size = int(payload["chunkSize"])
    chunk_count = int(payload["chunkCount"])
    meta = _meta_string(payload).encode("utf-8")

    tags = bytearray()
    collected = None if out_path else bytearray()
    sink = open(out_path, "wb") if out_path else None
    try:
        with open(data_path, "rb") as fi:
            if fi.read(len(STREAM_MAGIC)) != STREAM_MAGIC:
                raise ValueError("not a LockHTML stream container")
            for index in range(chunk_count):
                is_last = index == chunk_count - 1
                ct = fi.read() if is_last else fi.read(chunk_size + 16)
                if not ct:
                    raise ValueError("truncated stream container")
                plain = aes.decrypt(_chunk_nonce(base_iv, index), ct, _chunk_aad(index))
                tags += ct[-16:]
                if sink:
                    sink.write(plain)
                else:
                    collected += plain
            if fi.read(1):
                raise ValueError("stream container has trailing data")
    finally:
        if sink:
            sink.close()

    mac_input = bytes(meta + tags)
    expected = hmac.new(key, mac_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _unb64(payload["metamac"])):
        raise ValueError("integrity check failed")

    sig = payload.get("sig")
    if sig:
        pub = Ed25519PublicKey.from_public_bytes(_unb64(sig["pub"]))
        pub.verify(_unb64(sig["val"]), mac_input)

    return None if out_path else bytes(collected)


def render_viewer(payload: Dict[str, Any], template: Optional[str] = None) -> str:
    """Wrap an already-built payload in the viewer page (no encryption)."""
    tpl = template if template is not None else load_template(payload["kdf"])
    if PAYLOAD_PLACEHOLDER not in tpl:
        raise ValueError("viewer template is missing the __PAYLOAD__ placeholder")
    return tpl.replace(PAYLOAD_PLACEHOLDER, json.dumps(payload, separators=(",", ":")))


def stream_encrypt_bytes(data: Source, pin: Optional[str] = None, **kwargs: Any):
    """Convenience wrapper: returns ``(payload, sidecar_bytes)`` for small inputs."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src.bin")
        dst = os.path.join(tmp, "data.bin")
        with open(src, "wb") as fh:
            fh.write(_as_bytes(data))
        payload = stream_encrypt_file(src, pin, dst, **kwargs)
        with open(dst, "rb") as fh:
            return payload, fh.read()
