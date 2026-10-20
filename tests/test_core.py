"""Tests for the LockHTML cryptographic core and CLI (format v2)."""

from __future__ import annotations

import base64
import hashlib
import itertools
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
    STREAM_MAGIC,
    _gf_inv,
    _gf_mul,
    build_locked_html,
    build_shared_html,
    decrypt,
    encrypt,
    encrypt_shares,
    extract_payload,
    generate_recipient_key,
    generate_signing_key,
    load_recipient_key,
    parse_recipient_public,
    public_key_bytes,
    recipient_public_bytes,
    render_viewer,
    save_recipient_key,
    shamir_combine,
    shamir_split,
    stream_decrypt_file,
    stream_encrypt_bytes,
    stream_encrypt_shares_file,
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
    assert __version__ == "1.4.0"


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


# --- streaming container ---------------------------------------------------

def _sidecar(tmp_path, payload, sidecar):
    p = tmp_path / "data.bin"
    p.write_bytes(sidecar)
    return p


@pytest.mark.parametrize("kdf", ["pbkdf2", "argon2id"])
def test_stream_round_trip(tmp_path, kdf):
    data = os.urandom(200_000)
    payload, sidecar = stream_encrypt_bytes(data, "pin", kdf=kdf, chunk_size=65536)
    assert payload["container"] == "stream"
    assert payload["chunkCount"] == 4
    assert sidecar[:5] == STREAM_MAGIC
    # sidecar is raw ciphertext: ~= plaintext + 16 bytes/tag, no base64 inflation
    assert len(sidecar) == len(data) + 5 + 16 * payload["chunkCount"]
    assert stream_decrypt_file(str(_sidecar(tmp_path, payload, sidecar)), payload, "pin") == data


def test_stream_many_chunks(tmp_path):
    data = os.urandom(5 * (1 << 20))
    payload, sidecar = stream_encrypt_bytes(data, "p", kdf="pbkdf2", chunk_size=65536)
    assert payload["chunkCount"] == 80
    assert stream_decrypt_file(str(_sidecar(tmp_path, payload, sidecar)), payload, "p") == data


def test_stream_wrong_pin(tmp_path):
    payload, sidecar = stream_encrypt_bytes(os.urandom(1000), "pin", kdf="pbkdf2")
    with pytest.raises(Exception):
        stream_decrypt_file(str(_sidecar(tmp_path, payload, sidecar)), payload, "nope")


def test_stream_tampered_chunk_fails(tmp_path):
    payload, sidecar = stream_encrypt_bytes(os.urandom(200_000), "pin", kdf="pbkdf2", chunk_size=65536)
    bad = bytearray(sidecar)
    bad[10] ^= 0x01                      # flip a byte inside the first chunk
    with pytest.raises(Exception):
        stream_decrypt_file(str(_sidecar(tmp_path, payload, bytes(bad))), payload, "pin")


def test_stream_truncated_fails(tmp_path):
    payload, sidecar = stream_encrypt_bytes(os.urandom(200_000), "pin", kdf="pbkdf2", chunk_size=65536)
    with pytest.raises(Exception):
        stream_decrypt_file(str(_sidecar(tmp_path, payload, sidecar[:-20])), payload, "pin")


def test_stream_trailing_data_fails(tmp_path):
    payload, sidecar = stream_encrypt_bytes(os.urandom(1000), "pin", kdf="pbkdf2")
    with pytest.raises(Exception):
        stream_decrypt_file(str(_sidecar(tmp_path, payload, sidecar + b"junk")), payload, "pin")


def test_stream_metadata_tamper_fails(tmp_path):
    payload, sidecar = stream_encrypt_bytes(os.urandom(1000), "pin", kdf="pbkdf2")
    payload["chunkCount"] = 99            # attacker claims more chunks
    with pytest.raises(Exception):
        stream_decrypt_file(str(_sidecar(tmp_path, payload, sidecar)), payload, "pin")


def test_stream_keyfile(tmp_path):
    kf = b"stream-keyfile"
    payload, sidecar = stream_encrypt_bytes(os.urandom(1000), "pin", kdf="pbkdf2", keyfile=kf)
    p = _sidecar(tmp_path, payload, sidecar)
    assert stream_decrypt_file(str(p), payload, "pin", keyfile=kf)
    with pytest.raises(Exception):
        stream_decrypt_file(str(p), payload, "pin")


def test_stream_signature(tmp_path):
    key = generate_signing_key()
    payload, sidecar = stream_encrypt_bytes(os.urandom(1000), "pin", kdf="pbkdf2", sign_key=key)
    assert payload["sig"]["alg"] == "Ed25519"
    p = _sidecar(tmp_path, payload, sidecar)
    assert stream_decrypt_file(str(p), payload, "pin")
    payload["sig"]["val"] = base64.b64encode(os.urandom(64)).decode()
    with pytest.raises(Exception):
        stream_decrypt_file(str(p), payload, "pin")


def test_stream_out_path(tmp_path):
    data = os.urandom(150_000)
    payload, sidecar = stream_encrypt_bytes(data, "pin", kdf="pbkdf2", chunk_size=65536)
    out = tmp_path / "recovered.bin"
    assert stream_decrypt_file(str(_sidecar(tmp_path, payload, sidecar)), payload, "pin", str(out)) is None
    assert out.read_bytes() == data


def test_render_viewer_embeds_payload():
    payload, _ = stream_encrypt_bytes(b"hello", "pin", kdf="pbkdf2")
    html = render_viewer(payload)
    assert "__PAYLOAD__" not in html
    assert extract_payload(html)["container"] == "stream"


# --- X25519 recipient mode -------------------------------------------------

def _recipient():
    key = generate_recipient_key()
    return key, recipient_public_bytes(key)


def test_recipient_round_trip():
    key, pub = _recipient()
    payload = encrypt(DOC, recipient=pub)
    assert payload["mode"] == "recipient"
    assert payload["kdf"] == "x25519-hkdf"
    assert payload["pin"] is False
    assert len(base64.b64decode(payload["eph"])) == 32
    assert decrypt(payload, private_key=key) == DOC.encode()


def test_recipient_requires_private_key():
    _, pub = _recipient()
    payload = encrypt(DOC, recipient=pub)
    with pytest.raises(Exception):
        decrypt(payload)                      # no private key supplied


def test_recipient_wrong_key_fails():
    _, pub = _recipient()
    other, _ = _recipient()
    payload = encrypt(DOC, recipient=pub)
    with pytest.raises(Exception):
        decrypt(payload, private_key=other)


def test_recipient_with_pin():
    key, pub = _recipient()
    payload = encrypt(DOC, "4821", recipient=pub)
    assert payload["pin"] is True
    assert decrypt(payload, "4821", private_key=key) == DOC.encode()
    with pytest.raises(Exception):
        decrypt(payload, "0000", private_key=key)     # wrong PIN
    with pytest.raises(Exception):
        decrypt(payload, private_key=key)              # missing PIN


def test_recipient_with_keyfile():
    key, pub = _recipient()
    kf = b"recipient-keyfile"
    payload = encrypt(DOC, recipient=pub, keyfile=kf)
    assert decrypt(payload, keyfile=kf, private_key=key) == DOC.encode()
    with pytest.raises(Exception):
        decrypt(payload, private_key=key)              # missing keyfile


def test_recipient_ephemeral_is_random():
    _, pub = _recipient()
    a, b = encrypt(DOC, recipient=pub), encrypt(DOC, recipient=pub)
    assert a["eph"] != b["eph"]


def test_recipient_decoy_not_allowed():
    _, pub = _recipient()
    with pytest.raises(ValueError):
        encrypt(DOC, recipient=pub, decoy=("x", "y"))


def test_recipient_signed():
    key, pub = _recipient()
    signer = generate_signing_key()
    payload = encrypt(DOC, recipient=pub, sign_key=signer)
    assert verify_signature(payload) is True
    assert decrypt(payload, private_key=key) == DOC.encode()


def test_recipient_key_files(tmp_path):
    key = generate_recipient_key()
    path = tmp_path / "rec.pem"
    save_recipient_key(key, str(path))
    loaded = load_recipient_key(str(path))
    assert recipient_public_bytes(loaded) == recipient_public_bytes(key)


def test_parse_recipient_public_forms():
    key, pub = _recipient()
    b64 = base64.b64encode(pub).decode()
    assert parse_recipient_public(b64) == pub
    assert parse_recipient_public(b64 + "\n") == pub
    with pytest.raises(Exception):
        parse_recipient_public(base64.b64encode(b"too short").decode())


def test_recipient_stream_round_trip(tmp_path):
    key, pub = _recipient()
    data = os.urandom(150_000)
    payload, sidecar = stream_encrypt_bytes(data, recipient=pub, chunk_size=65536)
    assert payload["mode"] == "recipient"
    p = _sidecar(tmp_path, payload, sidecar)
    assert stream_decrypt_file(str(p), payload, private_key=key) == data
    with pytest.raises(Exception):
        stream_decrypt_file(str(p), payload)           # no key


def test_recipient_stream_with_pin(tmp_path):
    key, pub = _recipient()
    data = os.urandom(100_000)
    payload, sidecar = stream_encrypt_bytes(data, "4821", recipient=pub, chunk_size=65536)
    p = _sidecar(tmp_path, payload, sidecar)
    assert stream_decrypt_file(str(p), payload, "4821", private_key=key) == data
    with pytest.raises(Exception):
        stream_decrypt_file(str(p), payload, "0000", private_key=key)


def test_recipient_stream_metadata_tamper(tmp_path):
    key, pub = _recipient()
    payload, sidecar = stream_encrypt_bytes(os.urandom(1000), recipient=pub)
    payload["eph"] = base64.b64encode(os.urandom(32)).decode()
    with pytest.raises(Exception):
        stream_decrypt_file(str(_sidecar(tmp_path, payload, sidecar)), payload, private_key=key)


def test_cli_recipient(tmp_path):
    assert run_cli("keygen", "--type", "x25519", "-o", "rec.pem", cwd=tmp_path).returncode == 0
    assert (tmp_path / "rec.pem").is_file() and (tmp_path / "rec.pub").is_file()
    src = tmp_path / "doc.html"
    src.write_text(DOC, encoding="utf-8")
    out = tmp_path / "doc.locked.html"
    r = run_cli("lock", str(src), "--to", "rec.pub", "-o", str(out), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert extract_payload(out.read_text(encoding="utf-8"))["mode"] == "recipient"

    plain = tmp_path / "back.html"
    r = run_cli("unlock", str(out), "--key", "rec.pem", "-o", str(plain), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert plain.read_text(encoding="utf-8") == DOC

    # a different key must fail
    run_cli("keygen", "--type", "x25519", "-o", "other.pem", cwd=tmp_path)
    assert run_cli("unlock", str(out), "--key", "other.pem", cwd=tmp_path).returncode == 1


def test_cli_requires_pin_or_recipient(tmp_path):
    src = tmp_path / "doc.html"
    src.write_text(DOC, encoding="utf-8")
    assert run_cli("lock", str(src), cwd=tmp_path).returncode == 2


# --- Shamir secret sharing -----------------------------------------------

def test_gf_arithmetic():
    assert _gf_mul(0x57, 0x83) == 0xC1          # FIPS-197 AES example
    assert all(_gf_mul(a, _gf_inv(a)) == 1 for a in range(1, 256))


def test_shamir_round_trip():
    secret = os.urandom(32)
    shares = shamir_split(secret, 5, 3)
    assert len(shares) == 5
    assert all(len(s) == 33 for s in shares)
    for combo in itertools.combinations(shares, 3):
        assert shamir_combine(list(combo)) == secret


def test_shamir_insufficient_shares():
    secret = os.urandom(32)
    shares = shamir_split(secret, 5, 3)
    assert shamir_combine(shares[:2]) != secret


def test_shamir_edges():
    secret = os.urandom(16)
    assert shamir_combine(shamir_split(secret, 3, 1)[:1]) == secret   # k = 1
    assert shamir_combine(shamir_split(secret, 4, 4)) == secret       # k = n
    with pytest.raises(ValueError):
        shamir_split(secret, 2, 3)                                    # k > n


def test_shamir_rejects_bad_shares():
    shares = shamir_split(os.urandom(8), 3, 2)
    with pytest.raises(ValueError):
        shamir_combine([shares[0], shares[0]])                        # duplicate index
    with pytest.raises(ValueError):
        shamir_combine([bytes([0]) + shares[0][1:], shares[1]])       # index 0
    with pytest.raises(ValueError):
        shamir_combine([shares[0], shares[1][:-1]])                   # ragged


def test_shares_mode_round_trip():
    html, shares = build_shared_html(DOC, n=5, k=3)
    payload = extract_payload(html)
    assert payload["mode"] == "shares"
    assert payload["kdf"] == "shamir-hkdf"
    assert payload["kdfparams"] == {"info": "lockhtml/shamir", "n": 5, "k": 3}
    assert "ORION-7742" not in html
    assert unlock(html, shares=shares[:3]).decode() == DOC
    assert unlock(html, shares=[shares[0], shares[2], shares[4]]).decode() == DOC


def test_shares_insufficient_rejected():
    html, shares = build_shared_html(DOC, n=5, k=3)
    with pytest.raises(Exception):
        unlock(html, shares=shares[:2])
    with pytest.raises(Exception):
        unlock(html)                       # no shares at all


def test_shares_with_pin_and_keyfile():
    kf = b"shares-keyfile"
    html, shares = build_shared_html(DOC, "4821", n=3, k=2, keyfile=kf)
    assert unlock(html, "4821", keyfile=kf, shares=shares[:2]).decode() == DOC
    with pytest.raises(Exception):
        unlock(html, "0000", keyfile=kf, shares=shares[:2])
    with pytest.raises(Exception):
        unlock(html, "4821", shares=shares[:2])          # missing keyfile


def test_shares_decoy_not_allowed():
    # encrypt_shares has no decoy parameter, so passing one is a TypeError
    with pytest.raises(TypeError):
        build_shared_html(DOC, n=3, k=2, decoy=("x", "y"))


def test_shares_signed():
    signer = generate_signing_key()
    html, shares = build_shared_html(DOC, n=3, k=2, sign_key=signer)
    assert verify_signature(extract_payload(html)) is True
    assert unlock(html, shares=shares[:2]).decode() == DOC


def test_shares_bad_split_rejected():
    with pytest.raises(ValueError):
        encrypt_shares(DOC, n=2, k=3)
    with pytest.raises(ValueError):
        encrypt_shares(DOC, n=0, k=0)


def test_shares_stream_round_trip(tmp_path):
    data = os.urandom(200_000)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    sidecar = tmp_path / "d.bin"
    payload, shares = stream_encrypt_shares_file(
        str(src), None, str(sidecar), n=4, k=2, chunk_size=65536)
    assert payload["mode"] == "shares"
    assert stream_decrypt_file(str(sidecar), payload, shares=shares[:2]) == data
    with pytest.raises(Exception):
        stream_decrypt_file(str(sidecar), payload, shares=shares[:1])
    with pytest.raises(Exception):
        stream_decrypt_file(str(sidecar), payload)


def test_shares_stream_metadata_tamper(tmp_path):
    data = os.urandom(1000)
    src = tmp_path / "s.bin"
    src.write_bytes(data)
    sidecar = tmp_path / "d.bin"
    payload, shares = stream_encrypt_shares_file(str(src), None, str(sidecar), n=3, k=2)
    payload["kdfparams"] = {"info": "lockhtml/shamir", "n": 9, "k": 2}
    with pytest.raises(Exception):
        stream_decrypt_file(str(sidecar), payload, shares=shares[:2])


def test_cli_shares(tmp_path):
    src = tmp_path / "doc.txt"
    src.write_text("shared ORION-7742", encoding="utf-8")
    r = run_cli("lock", str(src), "--shares", "5:3", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    locked = tmp_path / "doc.locked.html"
    shares = tmp_path / "doc.locked.shares.txt"
    assert locked.is_file() and shares.is_file()
    lines = [x for x in shares.read_text().splitlines() if x.strip()]
    assert len(lines) == 5

    # any 3 work
    pick = tmp_path / "three.txt"
    pick.write_text("\n".join([lines[0], lines[2], lines[4]]), encoding="utf-8")
    out = tmp_path / "out.txt"
    assert run_cli("unlock", str(locked), "--shares", str(pick), "-o", str(out),
                   cwd=tmp_path).returncode == 0
    assert out.read_text(encoding="utf-8") == "shared ORION-7742"

    # --share repeatable
    assert run_cli("unlock", str(locked), "--share", lines[1], "--share", lines[3],
                   "--share", lines[0], "-o", str(out), cwd=tmp_path).returncode == 0

    # only 2 fails
    two = tmp_path / "two.txt"
    two.write_text("\n".join(lines[:2]), encoding="utf-8")
    assert run_cli("unlock", str(locked), "--shares", str(two), cwd=tmp_path).returncode == 1


def test_cli_shares_bad_spec(tmp_path):
    src = tmp_path / "d.txt"
    src.write_text("x", encoding="utf-8")
    assert run_cli("lock", str(src), "--shares", "3:5", cwd=tmp_path).returncode == 2
    assert run_cli("lock", str(src), "--shares", "nonsense", cwd=tmp_path).returncode == 2


def test_cli_shares_stream(tmp_path):
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(150_000))
    r = run_cli("lock", str(src), "--shares", "3:2", "--stream", "--chunk-size", "64", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    out = tmp_path / "out.bin"
    r = run_cli("unlock", str(tmp_path / "big.locked.html"), "--data", str(tmp_path / "big.locked.bin"),
                "--shares", str(tmp_path / "big.locked.shares.txt"), "-o", str(out), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert out.read_bytes() == src.read_bytes()


def test_cli_stream(tmp_path):
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(150_000))
    r = run_cli("lock", str(src), "--pin", "1", "--stream", "--chunk-size", "64", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    locked = tmp_path / "big.locked.html"
    sidecar = tmp_path / "big.locked.bin"
    assert locked.is_file() and sidecar.is_file()
    assert extract_payload(locked.read_text(encoding="utf-8"))["container"] == "stream"

    out = tmp_path / "out.bin"
    r = run_cli("unlock", str(locked), "--pin", "1", "-o", str(out), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert out.read_bytes() == src.read_bytes()

    assert run_cli("unlock", str(locked), "--pin", "wrong", "-o", str(out), cwd=tmp_path).returncode == 1
