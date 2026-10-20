#!/usr/bin/env python3
"""Verify the files produced by tools/e2e_gui.mjs with the Python core.

Usage:  python tools/e2e_gui_verify.py [dir]     (default: /tmp/lockhtml-gui)
"""
from __future__ import annotations

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from lockhtml.core import extract_payload, stream_decrypt_file, unlock  # noqa: E402

MARK = "ORION-7742 GUI"


def main() -> int:
    d = sys.argv[1] if len(sys.argv) > 1 else "/tmp/lockhtml-gui"
    j = lambda n: os.path.join(d, n)
    keyfile = base64.b64decode(open(j("gui_kf.b64")).read())

    checks = []
    for name, kf in [("gui_argon2.html", None), ("gui_pbkdf2.html", None), ("gui_keyfile.html", keyfile)]:
        text = open(j(name)).read()
        got = unlock(text, "4821", kf).decode()
        payload = extract_payload(text)
        checks.append((name, MARK in got and payload["watermark"] == "GUI-WM"))

    html = open(j("gui_stream.html")).read()
    payload = extract_payload(html)
    sidecar = j("gui_stream.bin")
    with open(sidecar, "wb") as fh:
        fh.write(base64.b64decode(open(j("gui_stream.bin.b64")).read()))
    got = stream_decrypt_file(sidecar, payload, "4821").decode()
    checks.append(("gui_stream.html", MARK in got and payload["container"] == "stream"))

    # recipient (X25519) files, locked by the browser, opened with the Python core
    priv = serialization.load_der_private_key(
        base64.b64decode(open(j("gui_recip_priv.b64")).read()), password=None)
    rtext = open(j("gui_recip.html")).read()
    rpayload = extract_payload(rtext)
    got = unlock(rtext, private_key=priv).decode()
    checks.append(("gui_recip.html", MARK in got and rpayload["mode"] == "recipient"))

    rhtml = open(j("gui_recip_stream.html")).read()
    rsp = extract_payload(rhtml)
    rside = j("gui_recip_stream.bin")
    with open(rside, "wb") as fh:
        fh.write(base64.b64decode(open(j("gui_recip_stream.bin.b64")).read()))
    got = stream_decrypt_file(rside, rsp, private_key=priv).decode()
    checks.append(("gui_recip_stream.html", MARK in got and rsp["mode"] == "recipient"))

    # Shamir shares files, locked by the browser, opened with the Python core
    sh_lines = [x for x in open(j("gui_shares.txt")).read().splitlines() if x.strip()]
    stext = open(j("gui_shares.html")).read()
    spayload = extract_payload(stext)
    got = unlock(stext, shares=sh_lines[:3]).decode()
    checks.append(("gui_shares.html", MARK in got and spayload["mode"] == "shares"))
    try:
        unlock(stext, shares=sh_lines[:2])
        checks.append(("gui_shares.html (2 of 3 rejected)", False))
    except Exception:
        checks.append(("gui_shares.html (2 of 3 rejected)", True))

    shtml = open(j("gui_shares_stream.html")).read()
    ssp = extract_payload(shtml)
    sside = j("gui_shares_stream.bin")
    with open(sside, "wb") as fh:
        fh.write(base64.b64decode(open(j("gui_shares_stream.bin.b64")).read()))
    ssl = [x for x in open(j("gui_shares_stream.shares.txt")).read().splitlines() if x.strip()]
    got = stream_decrypt_file(sside, ssp, shares=ssl[:2]).decode()
    checks.append(("gui_shares_stream.html", MARK in got and ssp["mode"] == "shares"))

    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}")
    failed = sum(1 for _, ok in checks if not ok)
    print(f"\n{len(checks) - failed}/{len(checks)} GUI->Python checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
