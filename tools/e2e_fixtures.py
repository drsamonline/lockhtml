#!/usr/bin/env python3
"""Generate the fixtures used by tools/e2e_browser.mjs.

Usage:  python tools/e2e_fixtures.py [outdir]     (default: /tmp/lockhtml-e2e)
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import base64  # noqa: E402

from lockhtml.core import (  # noqa: E402
    build_locked_html,
    build_shared_html,
    generate_recipient_key,
    generate_signing_key,
    recipient_public_bytes,
    render_viewer,
    save_recipient_key,
    save_signing_key,
    stream_encrypt_file,
    stream_encrypt_shares_file,
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
    stream("s_big", os.urandom(512 * 1024), kdf="pbkdf2", kind="file",
           name="big.bin", chunk_size=131072)
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

    # ---- X25519 recipient mode ----
    rkey = generate_recipient_key()
    save_recipient_key(rkey, p("rec.pem"))
    rpub = recipient_public_bytes(rkey)
    open(p("r_embedded.html"), "w").write(build_locked_html(DOC, recipient=rpub, kind="html"))
    open(p("r_pin.html"), "w").write(build_locked_html(DOC, PIN, recipient=rpub, kind="html"))
    open(p("r_file.html"), "w").write(
        build_locked_html(b"\x00\x01RECIPIENT", recipient=rpub, kind="file", name="r.bin"))
    rsrc = p("r_stream.src")
    with open(rsrc, "wb") as fh:
        fh.write(os.urandom(300_000))
    rp = stream_encrypt_file(rsrc, None, p("r_stream.bin"), recipient=rpub,
                             kind="file", name="rs.bin", chunk_size=65536)
    open(p("r_stream.html"), "w").write(render_viewer(rp))
    # a second, unrelated private key
    other = generate_recipient_key()
    save_recipient_key(other, p("other.pem"))

    open(p("rec.pub"), "w").write(base64.b64encode(rpub).decode() + "\n")

    # ---- Shamir shares mode ----
    sh_html, sh = build_shared_html(DOC, n=5, k=3)
    open(p("sh_embedded.html"), "w").write(sh_html)
    open(p("sh_embedded.shares.txt"), "w").write("\n".join(sh) + "\n")
    open(p("sh_two.txt"), "w").write("\n".join(sh[:2]) + "\n")

    sh_html2, sh2 = build_shared_html(DOC, PIN, n=3, k=2)
    open(p("sh_pin.html"), "w").write(sh_html2)
    open(p("sh_pin.shares.txt"), "w").write("\n".join(sh2) + "\n")

    ssrc = p("sh_stream.src")
    with open(ssrc, "wb") as fh:
        fh.write(os.urandom(300_000))
    sp, sh3 = stream_encrypt_shares_file(ssrc, None, p("sh_stream.bin"),
                                         n=4, k=2, kind="file", name="sb.bin", chunk_size=65536)
    open(p("sh_stream.html"), "w").write(render_viewer(sp))
    open(p("sh_stream.shares.txt"), "w").write("\n".join(sh3) + "\n")

    # ---- hidden volume + streaming decoy ----
    cover = "<!DOCTYPE html><html><body><h1>Cover</h1><p>COVER-1111</p></body></html>"
    real = "<!DOCTYPE html><html><body><h1>Real</h1><p>PISCES-9931</p></body></html>"
    open(p("hidden.html"), "w").write(build_locked_html(cover, PIN, hidden=[("0000", real)]))

    hsrc = p("hidden_stream.src")
    with open(hsrc, "wb") as fh:
        fh.write(os.urandom(200_000))
    hpl = stream_encrypt_file(
        hsrc, PIN, p("hidden_stream.bin"),
        decoy=("<!DOCTYPE html><html><body><p>DECOY-PAGE</p></body></html>", "0000"),
        kind="file", name="hs.bin", chunk_size=65536)
    open(p("hidden_stream.html"), "w").write(render_viewer(hpl))

    print(f"wrote fixtures to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
