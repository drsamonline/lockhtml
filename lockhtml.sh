#!/usr/bin/env sh
# LockHTML launcher — Linux / macOS / any POSIX shell.
#
#   ./lockhtml.sh lock secret.pdf --pin 4821
#   ./lockhtml.sh unlock secret.pdf.locked.html
#   ./lockhtml.sh gui
#
# Runs the CLI straight from this folder, so no install step is needed as long
# as Python 3.9+ and the two dependencies are available.

set -e

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Prefer a local virtualenv if one exists, then python3, then python.
PY=""
if [ -x "$DIR/.venv/bin/python" ]; then
  PY="$DIR/.venv/bin/python"
else
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
  done
fi

if [ -z "$PY" ]; then
  echo "LockHTML: Python 3.9+ was not found on your PATH." >&2
  echo "Install it from https://www.python.org/downloads/ and try again." >&2
  exit 1
fi

if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
  echo "LockHTML: Python 3.9 or newer is required (found: $("$PY" -V 2>&1))." >&2
  exit 1
fi

if ! "$PY" -c 'import argon2, cryptography' 2>/dev/null; then
  echo "LockHTML: the Python dependencies are not installed yet. Run:" >&2
  echo "  \"$PY\" -m pip install -r \"$DIR/requirements.txt\"" >&2
  echo "or, from the project folder:  \"$PY\" -m pip install -e ." >&2
  exit 1
fi

PYTHONPATH="$DIR${PYTHONPATH:+:$PYTHONPATH}" exec "$PY" -m lockhtml "$@"
