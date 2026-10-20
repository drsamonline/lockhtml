"""Tests for the LockHTML cryptographic core and CLI (format v2)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from lockhtml import __version__
from lockhtml.core import (
    ARGON2_PARAMS,
    FORMAT_VERSION,
    PBKDF2_PARAMS,
    build_locked_html,
    decrypt,
    encrypt,
    extract_payload,
    generate_signing_key,
    public_key_bytes,
    try_decoy,
    unlock,
    verify_signature,
)

DOC = "<!DOCTYPE html><html><body><h1>Secret</h1><p>ORION-7742</p></body></html>"


# --- core round trips ------------------------------------------------------

@pytest.mark.parametrize("kdf", ["pbkdf2", "argon2id"])
def test_round_trip(kdf):
    locked = build_locked_html(DOC, "4821", kdf=kdf)
    assert unlock(locked, "4821") == DOC.encode("utf-8")


@pytest.mark.parametrize("kdf", ["pbkdf2", "argon2id"])
def test_plaintext_not_present(kdf):
    locked = build_locked_html(DOC, "4821", kdf=kdf)
    assert "ORION-7742" not in locked
    assert "<h1>Secret</h1>" not in locked


def test_wrong_pin_fails():
    locked = build_locked_html(DOC, "4821")
    with pytest.raises(Exception):
        unlock(locked, "0000")


def test_payload_schema_v2():
    payload = encrypt(DOC, "4821", one_time=True, watermark="For A. Sharma")
    assert payload["v"] == FORMAT_VERSION
    assert payload["kdf"] == "argon2id"
    assert payload["kdfparams"] == ARGON2_PARAMS
    assert payload["onetime"] is True
    assert payload["maxviews"] == 1
    assert payload["watermark"] == "For A. Sharma"
    assert payload["kind"] == "html"
    for key in ("salt", "iv", "ct", "id"):
        assert isinstance(payload[key], str) and payload[key]


def test_pbkdf2_params():
    payload = encrypt(DOC, "4821", kdf="pbkdf2")
    assert payload["kdfparams"] == PBKDF2_PARAMS
    assert decrypt(payload, "4821") == DOC.encode()


# --- keyfile ---------------------------------------------------------------

def test_keyfile_required():
    kf = os.urandom(32)
    payload = encrypt(DOC, "4821", keyfile=kf)
    assert payload["keyfile"] is True
    assert decrypt(payload, "4821", kf) == DOC.encode()
    with pytest.raises(Exception):
        decrypt(payload, "4821")               # missing keyfile
    with pytest.raises(Exception):
        decrypt(payload, "4821", os.urandom(32))  # wrong keyfile


@pytest.mark.parametrize("kdf", ["pbkdf2", "argon2id"])
def test_keyfile_both_kdfs(kdf):
    kf = b"keyfile-bytes"
    payload = encrypt(DOC, "pin", kdf=kdf, keyfile=kf)
    assert decrypt(payload, "pin", kf) == DOC.encode()


# --- signing ---------------------------------------------------------------

def test_sign_and_verify():
    key = generate_signing_key()
    payload = encrypt(DOC, "4821", sign_key=key)
    assert payload["sig"]["alg"] == "Ed25519"
    assert verify_signature(payload) is True
    assert base64.b64decode(payload["sig"]["pub"]) == public_key_bytes(key)


def test_tampered_ciphertext_fails_verification():
    key = generate_signing_key()
    payload = encrypt(DOC, "4821", sign_key=key)
    ct = bytearray(base64.b64decode(payload["ct"]))
    ct[0] ^= 0x01
    payload["ct"] = base64.b64encode(bytes(ct)).decode()
    assert verify_signature(payload) is False


def test_no_signature_returns_none():
    assert verify_signature(encrypt(DOC, "4821")) is None


# --- decoy -----------------------------------------------------------------

def test_decoy_pin():
    decoy = "<html><body>nothing here</body></html>"
    payload = encrypt(DOC, "real", decoy=(decoy, "duress"))
    assert decrypt(payload, "real") == DOC.encode()
    assert try_decoy(payload, "duress") == decoy.encode()
    assert try_decoy(payload, "real") is None


# --- limits / metadata -----------------------------------------------------

def test_view_and_time_limits():
    payload = encrypt(DOC, "4821", max_views=3,
                      not_before="2026-01-01T00:00:00Z", expires="2027-01-01T00:00:00Z")
    assert payload["maxviews"] == 3
    assert payload["notbefore"].startswith("2026-01-01")
    assert payload["expires"].startswith("2027-01-01")


def test_file_kind_and_name():
    payload = encrypt(b"\x00\x01\x02binary", "4821", kind="file", name="report.pdf")
    assert payload["kind"] == "file"
    assert payload["name"] == "report.pdf"
    assert decrypt(payload, "4821") == b"\x00\x01\x02binary"


# --- misc ------------------------------------------------------------------

def test_salt_and_iv_random():
    a, b = encrypt(DOC, "4821"), encrypt(DOC, "4821")
    assert a["salt"] != b["salt"] and a["iv"] != b["iv"] and a["ct"] != b["ct"]


def test_unicode_content():
    doc = "<p>\u0928\u092e\u0938\u094d\u0924\u0947 \u2014 \u20b91,00,000</p>"
    assert unlock(build_locked_html(doc, "pin"), "pin").decode() == doc


def test_legacy_v1_payload_still_reads():
    salt, iv = os.urandom(16), os.urandom(12)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = hashlib.pbkdf2_hmac("sha256", b"4821", salt, 250000, dklen=32)
    ct = AESGCM(key).encrypt(iv, DOC.encode(), None)
    v1 = {"v": 1, "kdf": "PBKDF2-SHA256", "iter": 250000,
          "salt": base64.b64encode(salt).decode(), "iv": base64.b64encode(iv).decode(),
          "ct": base64.b64encode(ct).decode(), "id": "x", "onetime": False}
    assert decrypt(v1, "4821") == DOC.encode()


def test_template_selection_by_kdf():
    from lockhtml.core import load_template
    assert "__PAYLOAD__" in load_template("pbkdf2")
    assert "__PAYLOAD__" in load_template("argon2id")
    assert "argon2" in load_template("argon2id").lower()


def test_missing_placeholder_raises():
    with pytest.raises(ValueError):
        build_locked_html(DOC, "4821", template="<html>no placeholder</html>")


def test_extract_payload_invalid():
    with pytest.raises(ValueError):
        extract_payload("<html><body>nothing</body></html>")


def test_version():
    assert __version__ == "1.1.0"


# --- CLI -------------------------------------------------------------------

def run_cli(*args, cwd: Path):
    return subprocess.run([sys.executable, "-m", "lockhtml", *args],
                          cwd=cwd, capture_output=True, text=True)


def test_cli_lock_and_unlock(tmp_path):
    src = tmp_path / "doc.html"
    src.write_text(DOC, encoding="utf-8")
    r = run_cli("lock", str(src), "--pin", "4821", "--one-time", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    locked = tmp_path / "doc.locked.html"
    assert "ORION-7742" not in locked.read_text(encoding="utf-8")
    out = tmp_path / "out.html"
    r = run_cli("unlock", str(locked), "--pin", "4821", "-o", str(out), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert out.read_text(encoding="utf-8") == DOC


def test_cli_pbkdf2_and_argon2(tmp_path):
    src = tmp_path / "d.html"
    src.write_text(DOC, encoding="utf-8")
    for kdf in ("pbkdf2", "argon2id"):
        out = tmp_path / f"{kdf}.locked.html"
        r = run_cli("lock", str(src), "--pin", "1", "--kdf", kdf, "-o", str(out), cwd=tmp_path)
        assert r.returncode == 0, r.stderr
        payload = extract_payload(out.read_text(encoding="utf-8"))
        assert payload["kdf"] == kdf
        assert unlock(out.read_text(encoding="utf-8"), "1") == DOC.encode()


def test_cli_keyfile(tmp_path):
    src = tmp_path / "d.html"
    src.write_text(DOC, encoding="utf-8")
    kf = tmp_path / "k.key"
    kf.write_bytes(b"super-secret-keyfile")
    out = tmp_path / "d.locked.html"
    r = run_cli("lock", str(src), "--pin", "1", "--keyfile", str(kf), "-o", str(out), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert run_cli("unlock", str(out), "--pin", "1", cwd=tmp_path).returncode == 1
    assert run_cli("unlock", str(out), "--pin", "1", "--keyfile", str(kf), cwd=tmp_path).returncode == 0


def test_cli_keygen_and_sign(tmp_path):
    key = tmp_path / "sign.pem"
    assert run_cli("keygen", "-o", str(key), cwd=tmp_path).returncode == 0
    assert key.is_file()
    src = tmp_path / "d.html"
    src.write_text(DOC, encoding="utf-8")
    out = tmp_path / "d.locked.html"
    r = run_cli("lock", str(src), "--pin", "1", "--sign", str(key), "-o", str(out), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert verify_signature(extract_payload(out.read_text(encoding="utf-8"))) is True


def test_cli_keygen_refuses_overwrite(tmp_path):
    key = tmp_path / "sign.pem"
    assert run_cli("keygen", "-o", str(key), cwd=tmp_path).returncode == 0
    assert run_cli("keygen", "-o", str(key), cwd=tmp_path).returncode == 2


def test_cli_missing_file(tmp_path):
    assert run_cli("lock", "nope.html", "--pin", "1", cwd=tmp_path).returncode == 2


def test_cli_binary_file_kind(tmp_path):
    src = tmp_path / "data.bin"
    src.write_bytes(b"\x00\xff\x10binary")
    out = tmp_path / "data.locked.html"
    r = run_cli("lock", str(src), "--pin", "1", "-o", str(out), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    payload = extract_payload(out.read_text(encoding="utf-8"))
    assert payload["kind"] == "file" and payload["name"] == "data.bin"
    assert unlock(out.read_text(encoding="utf-8"), "1") == b"\x00\xff\x10binary"
