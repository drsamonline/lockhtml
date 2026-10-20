#!/usr/bin/env python3
"""Generate the fixtures used by tools/e2e_browser.mjs.

Usage:  python tools/e2e_fixtures.py [outdir]     (default: /tmp/lockhtml-e2e)
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from lockhtml.core import (  # noqa: E402
    build_locked_html,
    generate_signing_key,
    render_viewer,
    save_signing_key,
    stream_encrypt_file,
)

DOC = "<!DOCTYPE html><html><body><h1>Secret</h1><p>ORION-7742</p></body></html>"
PIN = "4821"
KEYFILE = b"the-keyfile-bytes-0123456789abcdef"


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/lockhtml-e2e"
    os.makedirs(out, exist_ok=True)
    p = lambda name: os.path.join(out, name)

    # ---- embedded container ----
    open(p("a_argon2.html"), "w").write(build_locked_html(DOC, PIN, kdf="argon2id"))
    open(p("b_pbkdf2.html"), "w").write(build_locked_html(DOC, PIN, kdf="pbkdf2"))
    open(p("kf.bin"), "wb").write(KEYFILE)
    open(p("c_keyfile.html"), "w").write(build_locked_html(DOC, PIN, keyfile=KEYFILE))
    open(p("d_maxviews.html"), "w").write(build_locked_html(DOC, PIN, max_views=2))
    key = generate_signing_key()
    save_signing_key(key, p("sign.pem"))
    open(p("e_signed.html"), "w").write(build_locked_html(DOC, PIN, sign_key=key))
    open(p("f_watermark.html"), "w").write(build_locked_html(DOC, PIN, watermark="CONFIDENTIAL"))
    open(p("g_file.html"), "w").write(
        build_locked_html(b"\x00\x01BINARYDATA", PIN, kind="file", name="data.bin"))
    open(p("h_decoy.html"), "w").write(build_locked_html(
        DOC, "realpin",
        decoy=("<!DOCTYPE html><html><body><h2>No content</h2></body></html>", "duress")))

    # ---- streaming container ----
    def stream(fname, data, **kw):
        src = p(fname + ".src")
        with open(src, "wb") as fh:
            fh.write(data)
        payload = stream_encrypt_file(src, PIN, p(fname + ".bin"), **kw)
        open(p(fname + ".html"), "w").write(render_viewer(payload))

    stream("s_html", DOC.encode(), kdf="pbkdf2", kind="html", chunk_size=65536)
    stream("s_big", os.urandom(2 * 1024 * 1024), kdf="pbkdf2", kind="file",
           name="big.bin", chunk_size=262144)
    stream("s_argon2", os.urandom(300_000), kdf="argon2id", kind="file",
           name="a.bin", chunk_size=65536)
    stream("s_keyfile", os.urandom(200_000), kdf="pbkdf2", kind="file",
           name="k.bin", chunk_size=65536, keyfile=KEYFILE)
    stream("s_signed", os.urandom(150_000), kdf="pbkdf2", kind="file",
           name="s.bin", chunk_size=65536, sign_key=key)

    # tampered sidecar
    raw = bytearray(open(p("s_html.bin"), "rb").read())
    raw[20] ^= 0x01
    open(p("s_html_tampered.bin"), "wb").write(bytes(raw))

    print(f"wrote fixtures to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
