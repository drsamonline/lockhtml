#!/usr/bin/env python3
"""Generate the standalone GUI (lockhtml/gui/index.html).

The GUI is a single self-contained HTML file that runs in any browser. It needs
a copy of the viewer template so that files it produces are byte-compatible with
the CLI. Rather than maintain two copies, this script inlines the canonical
viewer template (lockhtml/templates/viewer.html) into the GUI source
(lockhtml/gui/app.html).

Run from anywhere:

    python tools/build_gui.py
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
VIEWER = ROOT / "lockhtml" / "templates" / "viewer.html"
APP = ROOT / "lockhtml" / "gui" / "app.html"
OUT = ROOT / "lockhtml" / "gui" / "index.html"
PLACEHOLDER = '"__VIEWER_TEMPLATE__"'


def main() -> int:
    viewer = VIEWER.read_text(encoding="utf-8")
    app = APP.read_text(encoding="utf-8")

    if PLACEHOLDER not in app:
        print(f"error: {APP} is missing the {PLACEHOLDER} placeholder", file=sys.stderr)
        return 1
    if app.count(PLACEHOLDER) != 1:
        print("error: placeholder appears more than once", file=sys.stderr)
        return 1

    # JSON-encode, then escape "<" so the string cannot break out of <script>.
    injected = json.dumps(viewer).replace("<", "\\u003c")
    out = app.replace(PLACEHOLDER, injected)
    OUT.write_text(out, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(out):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
