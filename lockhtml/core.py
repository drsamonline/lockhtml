"""Cryptographic core for LockHTML.

A locked file is an ordinary HTML page (the *viewer*) with a JSON *payload*
embedded in a ``<script id="payload" type="application/json">`` tag. The
payload holds the salt, IV and ciphertext; the original document never appears
in plaintext.

Payload schema
--------------
{
  "v":       1,                 # format version
  "kdf":     "PBKDF2-SHA256",   # key derivation function
  "iter":    250000,            # PBKDF2 iterations
  "salt":    "<base64>",        # 16 random bytes
  "iv":      "<base64>",        # 12 random bytes (AES-GCM nonce)
  "ct":      "<base64>",        # AES-256-GCM ciphertext + tag
  "id":      "<hex>",           # short id of the ciphertext (burn flag key)
  "onetime": true | false       # expire after first successful view
}
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from importlib import resources
from typing import Any, Dict, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: PBKDF2 iteration count. High enough to be expensive to brute-force.
ITERATIONS = 250_000
#: Key derivation function identifier stored in the payload.
KDF = "PBKDF2-SHA256"
#: Placeholder in the viewer template that is replaced with the payload JSON.
PAYLOAD_PLACEHOLDER = "__PAYLOAD__"
#: Regex used to pull the payload back out of a locked file.
_PAYLOAD_RE = re.compile(
    r'<script id="payload" type="application/json">(.*?)</script>', re.DOTALL
)

Source = Union[str, bytes]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data)


def derive_key(pin: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    """Derive a 256-bit AES key from ``pin`` and ``salt`` using PBKDF2-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256", pin.encode("utf-8"), salt, iterations, dklen=32
    )


def encrypt(
    data: Source,
    pin: str,
    one_time: bool = False,
    iterations: int = ITERATIONS,
) -> Dict[str, Any]:
    """Encrypt ``data`` under ``pin`` and return the payload dictionary."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(pin, salt, iterations)
    ciphertext = AESGCM(key).encrypt(iv, data, None)

    return {
        "v": 1,
        "kdf": KDF,
        "iter": iterations,
        "salt": _b64(salt),
        "iv": _b64(iv),
        "ct": _b64(ciphertext),
        "id": hashlib.sha256(ciphertext).hexdigest()[:16],
        "onetime": bool(one_time),
    }


def decrypt(payload: Dict[str, Any], pin: str) -> str:
    """Decrypt a payload with ``pin``; raises ``InvalidTag`` on a wrong PIN."""
    salt = _unb64(payload["salt"])
    iv = _unb64(payload["iv"])
    ciphertext = _unb64(payload["ct"])
    key = derive_key(pin, salt, int(payload.get("iter", ITERATIONS)))
    return AESGCM(key).decrypt(iv, ciphertext, None).decode("utf-8")


def load_template() -> str:
    """Return the viewer template shipped inside the package."""
    return (
        resources.files("lockhtml")
        .joinpath("templates/viewer.html")
        .read_text(encoding="utf-8")
    )


def build_locked_html(
    source: Source,
    pin: str,
    one_time: bool = False,
    iterations: int = ITERATIONS,
    template: str | None = None,
) -> str:
    """Encrypt ``source`` and return the complete locked HTML document."""
    payload = encrypt(source, pin, one_time, iterations)
    tpl = template if template is not None else load_template()
    if PAYLOAD_PLACEHOLDER not in tpl:
        raise ValueError("viewer template is missing the __PAYLOAD__ placeholder")
    return tpl.replace(PAYLOAD_PLACEHOLDER, json.dumps(payload))


def extract_payload(locked_html: str) -> Dict[str, Any]:
    """Extract the embedded payload from a locked HTML document."""
    match = _PAYLOAD_RE.search(locked_html)
    if not match:
        raise ValueError("no LockHTML payload found in this file")
    return json.loads(match.group(1))


def unlock(locked_html: str, pin: str) -> str:
    """Decrypt a locked HTML document back to its original plaintext."""
    return decrypt(extract_payload(locked_html), pin)
