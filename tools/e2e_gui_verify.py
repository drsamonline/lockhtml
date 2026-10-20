#!/usr/bin/env python3
"""Verify the files produced by tools/e2e_gui.mjs with the Python core.

Usage:  python tools/e2e_gui_verify.py [dir]     (default: /tmp/lockhtml-gui)
"""
from __future__ import annotations

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

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

    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}")
    failed = sum(1 for _, ok in checks if not ok)
    print(f"\n{len(checks) - failed}/{len(checks)} GUI->Python checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
