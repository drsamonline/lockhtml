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
import os
import re
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Dict, Optional, Tuple, Union

from argon2.low_level import Type as _Argon2Type
from argon2.low_level import hash_secret_raw as _argon2_raw
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
    pin: str,
    *,
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
) -> Dict[str, Any]:
    """Encrypt ``data`` under ``pin`` and return a v2 payload dictionary."""
    if kdfparams is None:
        kdfparams = ARGON2_PARAMS if kdf == "argon2id" else PBKDF2_PARAMS

    blob = _encrypt_blob(_as_bytes(data), pin, kdf, kdfparams, keyfile)
    ciphertext = _unb64(blob["ct"])

    if one_time and max_views is None:
        max_views = 1

    payload: Dict[str, Any] = {
        "v": FORMAT_VERSION,
        "kind": kind,
        "name": name,
        "kdf": kdf,
        "kdfparams": dict(kdfparams),
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

    return payload


def _decrypt_blob(blob: Dict[str, Any], pin: str, keyfile: Optional[bytes]) -> bytes:
    kdf = blob.get("kdf", DEFAULT_KDF)
    kdfparams = blob.get("kdfparams")
    if kdfparams is None and "iter" in blob:  # legacy v1
        kdfparams = {"iter": blob["iter"]}
    key = derive_key(pin, _unb64(blob["salt"]), kdf, kdfparams, keyfile)
    return AESGCM(key).decrypt(_unb64(blob["iv"]), _unb64(blob["ct"]), None)


def decrypt(payload: Dict[str, Any], pin: str, keyfile: Optional[bytes] = None) -> bytes:
    """Decrypt a payload with ``pin``; raises ``InvalidTag`` on a wrong PIN."""
    return _decrypt_blob(payload, pin, keyfile)


def try_decoy(payload: Dict[str, Any], pin: str, keyfile: Optional[bytes] = None):
    """Return the decoy plaintext if ``pin`` opens it, else None."""
    decoy = payload.get("decoy")
    if not decoy:
        return None
    try:
        return _decrypt_blob(decoy, pin, keyfile)
    except Exception:
        return None


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
    pin: str,
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


def unlock(locked_html: str, pin: str, keyfile: Optional[bytes] = None) -> bytes:
    """Decrypt a locked HTML document back to its original plaintext bytes."""
    return decrypt(extract_payload(locked_html), pin, keyfile)
