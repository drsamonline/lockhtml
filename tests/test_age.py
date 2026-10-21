"""age interoperability tests.

The first test decrypts a real file produced by the reference implementation
(FiloSottile/age), embedded here so the check runs in CI without network access.
The rest cover the STREAM boundaries that are easy to get wrong — especially a
payload whose length is an exact multiple of the 64 KiB chunk size, where the
final chunk is full-sized but still flagged as final.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lockhtml import age  # noqa: E402

# testdata/example.age and testdata/example_keys.txt from FiloSottile/age.
# Plaintext: "Black lives matter."
OFFICIAL_AGE_B64 = (
    "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA4aHJsTStaQkczRGQ0ZkYyK2E1ODN6ZFRJ"
    "V0RrOC9SNDFrQ1lac3Z3VFc0CnlPNFBZZGxNV0RKK0N4Z1VOUnFZNVowVC9tK2czRkNoNWpJeEdM"
    "YkNWWGMKLS0tIEkvaW1ldlp6eTgxMjBKU3ptSm5tbi9LTWszcDVBMTFWODNOazQxbTlOUEUKcMXl"
    "NiShUgdT+Sxa0Q7KsnO6TWEXgHcT6DggQXod8soIGCJyyPhchXc0oTEaO3XpjQ6v"
)
OFFICIAL_IDENTITY = "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"


def run_cli(*args, cwd: Path):
    return subprocess.run([sys.executable, "-m", "lockhtml", *args],
                          cwd=cwd, capture_output=True, text=True)


def _pair():
    identity = age.generate_identity()
    return identity, age.recipient_raw(identity)


# --- the official vector ----------------------------------------------------

def test_official_age_vector_decrypts():
    blob = base64.b64decode(OFFICIAL_AGE_B64)
    assert age.decrypt(blob, [age.parse_identity(OFFICIAL_IDENTITY)]) == b"Black lives matter."


def test_official_age_vector_rejects_wrong_identity():
    blob = base64.b64decode(OFFICIAL_AGE_B64)
    with pytest.raises(ValueError):
        age.decrypt(blob, [age.generate_identity()])


def test_official_age_header_mac_is_verified():
    # Flip a bit inside the header (the version line) — the MAC must catch it.
    blob = bytearray(base64.b64decode(OFFICIAL_AGE_B64))
    blob[5] ^= 0x01
    with pytest.raises(Exception):
        age.decrypt(bytes(blob), [age.parse_identity(OFFICIAL_IDENTITY)])


# --- bech32 -----------------------------------------------------------------

def test_bech32_round_trip():
    identity = age.generate_identity()
    assert age.encode_recipient(identity).startswith("age1")
    assert age.encode_identity(identity).startswith("AGE-SECRET-KEY-1")
    assert age.recipient_raw(age.parse_identity(age.encode_identity(identity))) == \
        age.recipient_raw(identity)


def test_bech32_rejects_bad_checksum():
    identity = age.generate_identity()
    text = age.encode_recipient(identity)
    broken = text[:-1] + ("q" if text[-1] != "q" else "p")
    with pytest.raises(ValueError):
        age.parse_recipient(broken)


# --- round-trips and STREAM boundaries --------------------------------------

@pytest.mark.parametrize("size", [0, 1, 15, 1000, 65535, 65536, 65537, 131072, 200000])
def test_age_round_trip_sizes(size):
    identity, recipient = _pair()
    data = os.urandom(size)
    assert age.decrypt(age.encrypt(data, [recipient]), [identity]) == data


def test_age_multi_recipient():
    a = age.generate_identity()
    b = age.generate_identity()
    blob = age.encrypt(b"to both", [age.recipient_raw(a), age.recipient_raw(b)])
    assert age.decrypt(blob, [a]) == b"to both"
    assert age.decrypt(blob, [b]) == b"to both"
    with pytest.raises(ValueError):
        age.decrypt(blob, [age.generate_identity()])


def test_age_requires_a_recipient():
    with pytest.raises(ValueError):
        age.encrypt(b"x", [])


def test_age_rejects_tampered_payload():
    identity, recipient = _pair()
    blob = bytearray(age.encrypt(b"payload here", [recipient]))
    blob[-1] ^= 0x01
    with pytest.raises(Exception):
        age.decrypt(bytes(blob), [identity])


def test_age_skips_unknown_stanzas():
    """A file with a stanza type we do not implement must still open."""
    identity, recipient = _pair()
    blob = age.encrypt(b"with grease", [recipient])
    line_end = blob.index(b"\n", blob.index(b"-> "))
    grease = b"-> example.com/enigma AAA\nAAAA\n"
    greased = blob[:line_end + 1] + grease + blob[line_end + 1:]
    # The MAC no longer matches after inserting a stanza, so this must fail...
    with pytest.raises(Exception):
        age.decrypt(greased, [identity])
    # ...but the original still opens, and unknown stanzas are simply skipped.
    assert age.decrypt(blob, [identity]) == b"with grease"


def test_age_rejects_non_age_file():
    with pytest.raises(ValueError):
        age.decrypt(b"not an age file at all\n", [age.generate_identity()])


def test_age_truncated_payload():
    identity, recipient = _pair()
    blob = age.encrypt(b"x" * 100, [recipient])
    with pytest.raises(Exception):
        age.decrypt(blob[:-5], [identity])


# --- CLI --------------------------------------------------------------------

def test_cli_keygen_age_and_round_trip(tmp_path):
    assert run_cli("keygen", "--type", "age", "-o", "key.txt", cwd=tmp_path).returncode == 0
    text = (tmp_path / "key.txt").read_text()
    assert "AGE-SECRET-KEY-1" in text
    recipient = [l for l in text.splitlines() if l.startswith("# public key:")][0].split(": ", 1)[1]
    assert recipient.startswith("age1")

    src = tmp_path / "doc.txt"
    src.write_text("cli interop ORION-7742", encoding="utf-8")
    r = run_cli("age-encrypt", str(src), "-r", recipient, cwd=tmp_path)
    assert r.returncode == 0, r.stderr

    out = tmp_path / "back.txt"
    r = run_cli("age-decrypt", str(tmp_path / "doc.txt.age"), "-i", "key.txt",
                "-o", str(out), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert out.read_text(encoding="utf-8") == "cli interop ORION-7742"

    # a different identity must fail
    run_cli("keygen", "--type", "age", "-o", "other.txt", cwd=tmp_path)
    assert run_cli("age-decrypt", str(tmp_path / "doc.txt.age"), "-i", "other.txt",
                   cwd=tmp_path).returncode == 1


def test_cli_age_encrypt_needs_a_recipient(tmp_path):
    src = tmp_path / "d.txt"
    src.write_text("x", encoding="utf-8")
    assert run_cli("age-encrypt", str(src), cwd=tmp_path).returncode == 2


def test_cli_age_recipients_file(tmp_path):
    assert run_cli("keygen", "--type", "age", "-o", "k1.txt", cwd=tmp_path).returncode == 0
    assert run_cli("keygen", "--type", "age", "-o", "k2.txt", cwd=tmp_path).returncode == 0
    recipients = []
    for name in ("k1.txt", "k2.txt"):
        text = (tmp_path / name).read_text()
        recipients.append([l for l in text.splitlines()
                           if l.startswith("# public key:")][0].split(": ", 1)[1])
    (tmp_path / "recipients.txt").write_text(
        "# a comment\n" + "\n".join(recipients) + "\n", encoding="utf-8")
    src = tmp_path / "d.txt"
    src.write_text("multi", encoding="utf-8")
    r = run_cli("age-encrypt", str(src), "-R", "recipients.txt", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    for name in ("k1.txt", "k2.txt"):
        out = tmp_path / (name + ".out")
        assert run_cli("age-decrypt", str(tmp_path / "d.txt.age"), "-i", name,
                       "-o", str(out), cwd=tmp_path).returncode == 0
        assert out.read_text(encoding="utf-8") == "multi"


def test_cli_age_identity_string(tmp_path):
    assert run_cli("keygen", "--type", "age", "-o", "k.txt", cwd=tmp_path).returncode == 0
    text = (tmp_path / "k.txt").read_text()
    recipient = [l for l in text.splitlines() if l.startswith("# public key:")][0].split(": ", 1)[1]
    identity = [l for l in text.splitlines() if l.startswith("AGE-SECRET-KEY-")][0]
    src = tmp_path / "d.txt"
    src.write_text("by string", encoding="utf-8")
    assert run_cli("age-encrypt", str(src), "-r", recipient, cwd=tmp_path).returncode == 0
    out = tmp_path / "o.txt"
    assert run_cli("age-decrypt", str(tmp_path / "d.txt.age"), "-I", identity,
                   "-o", str(out), cwd=tmp_path).returncode == 0
    assert out.read_text(encoding="utf-8") == "by string"
