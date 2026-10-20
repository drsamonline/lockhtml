#!/usr/bin/env python3
"""Build LockHTML's generated assets.

Produces, from source:

  lockhtml/templates/viewer.html          viewer, PBKDF2 only (small)
  lockhtml/templates/viewer-argon2.html   viewer with the Argon2id WASM inlined
  lockhtml/gui/index.html                 the standalone GUI, with both viewers
                                          inlined so it can lock with either KDF

Sources:
  lockhtml/templates/viewer.src.html      viewer source (markers: __PAYLOAD__, <!--__ARGON2__-->)
  lockhtml/gui/app.html                   GUI source (markers: "__VIEWER_TEMPLATE__", "__VIEWER_TEMPLATE_ARGON2__")
  node_modules/argon2-browser/dist/argon2-bundled.min.js   Argon2id WASM runtime

Run:  python tools/build.py
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARGON2_JS = ROOT / "node_modules/argon2-browser/dist/argon2-bundled.min.js"
VIEWER_SRC = ROOT / "lockhtml/templates/viewer.src.html"
VIEWER = ROOT / "lockhtml/templates/viewer.html"
VIEWER_A2 = ROOT / "lockhtml/templates/viewer-argon2.html"
APP = ROOT / "lockhtml/gui/app.html"
GUI = ROOT / "lockhtml/gui/index.html"

ARGON2_MARK = "<!--__ARGON2__-->"
GUI_MARK = '"__VIEWER_TEMPLATE__"'
GUI_MARK_A2 = '"__VIEWER_TEMPLATE_ARGON2__"'
PAYLOAD_MARK = "__PAYLOAD__"


def js_string(html: str) -> str:
    """Encode HTML as a JS string literal that cannot break out of <script>."""
    return json.dumps(html).replace("<", "\\u003c")


def main() -> int:
    if not ARGON2_JS.is_file():
        print(f"error: {ARGON2_JS} not found — run `npm install` first", file=sys.stderr)
        return 1
    argon2_js = ARGON2_JS.read_text(encoding="utf-8")
    if "</script" in argon2_js.lower():
        print("error: argon2 bundle contains a script-closing sequence", file=sys.stderr)
        return 1

    viewer_src = VIEWER_SRC.read_text(encoding="utf-8")
    if ARGON2_MARK not in viewer_src or PAYLOAD_MARK not in viewer_src:
        print("error: viewer source is missing a required marker", file=sys.stderr)
        return 1

    viewer_plain = viewer_src.replace(ARGON2_MARK, "")
    viewer_argon2 = viewer_src.replace(ARGON2_MARK, "<script>" + argon2_js + "</script>")
    VIEWER.write_text(viewer_plain, encoding="utf-8")
    VIEWER_A2.write_text(viewer_argon2, encoding="utf-8")

    app = APP.read_text(encoding="utf-8")
    for mark in (GUI_MARK, GUI_MARK_A2, ARGON2_MARK):
        if app.count(mark) != 1:
            print(f"error: {APP} must contain exactly one {mark}", file=sys.stderr)
            return 1
    app = app.replace(ARGON2_MARK, "<script>" + argon2_js + "</script>")
    gui = app.replace(GUI_MARK_A2, js_string(viewer_argon2)).replace(GUI_MARK, js_string(viewer_plain))
    GUI.write_text(gui, encoding="utf-8")

    for p in (VIEWER, VIEWER_A2, GUI):
        print(f"wrote {p.relative_to(ROOT)} ({p.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
