"""Tests for the LockHTML cryptographic core and CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from lockhtml import __version__
from lockhtml.core import (
    ITERATIONS,
    build_locked_html,
    decrypt,
    encrypt,
    extract_payload,
    unlock,
)

DOC = "<!DOCTYPE html><html><body><h1>Secret</h1><p>ORION-7742</p></body></html>"


def test_round_trip():
    locked = build_locked_html(DOC, "4821")
    assert unlock(locked, "4821") == DOC


def test_plaintext_not_present():
    locked = build_locked_html(DOC, "4821")
    assert "ORION-7742" not in locked
    assert "<h1>Secret</h1>" not in locked


def test_wrong_pin_fails():
    locked = build_locked_html(DOC, "4821")
    with pytest.raises(Exception):
        unlock(locked, "0000")


def test_payload_schema():
    payload = encrypt(DOC, "4821", one_time=True)
    assert payload["v"] == 1
    assert payload["kdf"] == "PBKDF2-SHA256"
    assert payload["iter"] == ITERATIONS
    assert payload["onetime"] is True
    for key in ("salt", "iv", "ct", "id"):
        assert isinstance(payload[key], str) and payload[key]
    assert decrypt(payload, "4821") == DOC


def test_extract_payload_roundtrip():
    locked = build_locked_html(DOC, "4821")
    payload = extract_payload(locked)
    assert decrypt(payload, "4821") == DOC


def test_salt_and_iv_are_random():
    a = encrypt(DOC, "4821")
    b = encrypt(DOC, "4821")
    assert a["salt"] != b["salt"]
    assert a["iv"] != b["iv"]
    assert a["ct"] != b["ct"]


def test_unicode_content():
    doc = "<p>\u0928\u092e\u0938\u094d\u0924\u0947 \u2014 \u20b91,00,000</p>"
    assert unlock(build_locked_html(doc, "pin"), "pin") == doc


def test_iterations_override():
    payload = encrypt(DOC, "4821", iterations=1000)
    assert payload["iter"] == 1000
    assert decrypt(payload, "4821") == DOC


def test_missing_placeholder_raises():
    with pytest.raises(ValueError):
        build_locked_html(DOC, "4821", template="<html>no placeholder</html>")


def test_extract_payload_invalid():
    with pytest.raises(ValueError):
        extract_payload("<html><body>nothing here</body></html>")


def test_version():
    assert __version__


# --- CLI ------------------------------------------------------------------

def run_cli(*args: str, cwd: Path):
    return subprocess.run(
        [sys.executable, "-m", "lockhtml", *args],
        cwd=cwd, capture_output=True, text=True,
    )


def test_cli_lock_and_unlock(tmp_path: Path):
    src = tmp_path / "doc.html"
    src.write_text(DOC, encoding="utf-8")

    result = run_cli("lock", str(src), "--pin", "4821", "--one-time", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    locked = tmp_path / "doc.locked.html"
    assert locked.is_file()
    assert "ORION-7742" not in locked.read_text(encoding="utf-8")

    out = tmp_path / "out.html"
    result = run_cli("unlock", str(locked), "--pin", "4821", "-o", str(out), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert out.read_text(encoding="utf-8") == DOC


def test_cli_unlock_wrong_pin(tmp_path: Path):
    src = tmp_path / "doc.html"
    src.write_text(DOC, encoding="utf-8")
    run_cli("lock", str(src), "--pin", "4821", cwd=tmp_path)
    result = run_cli("unlock", str(tmp_path / "doc.locked.html"),
                     "--pin", "9999", cwd=tmp_path)
    assert result.returncode == 1


def test_cli_lock_multiple(tmp_path: Path):
    for name in ("a.html", "b.html"):
        (tmp_path / name).write_text(DOC, encoding="utf-8")
    outdir = tmp_path / "locked"
    result = run_cli("lock", "a.html", "b.html", "--pin", "1",
                     "--outdir", str(outdir), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert (outdir / "a.locked.html").is_file()
    assert (outdir / "b.locked.html").is_file()


def test_cli_missing_file(tmp_path: Path):
    result = run_cli("lock", "nope.html", "--pin", "1", cwd=tmp_path)
    assert result.returncode == 2
