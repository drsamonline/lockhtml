"""Command-line interface for LockHTML."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import webbrowser
from pathlib import Path

from . import __version__
from .core import build_locked_html, unlock

LOCKED_SUFFIX = ".locked.html"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def cmd_lock(args: argparse.Namespace) -> int:
    inputs = [Path(p) for p in args.input]
    missing = [p for p in inputs if not p.is_file()]
    if missing:
        for p in missing:
            print(f"error: no such file: {p}", file=sys.stderr)
        return 2

    if args.output and len(inputs) > 1:
        print("error: -o/--output can only be used with a single input file",
              file=sys.stderr)
        return 2

    outdir = Path(args.outdir) if args.outdir else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)

    rc = 0
    for src in inputs:
        try:
            source = _read_text(src)
            locked = build_locked_html(source, args.pin, args.one_time,
                                       args.iterations)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"error: {src}: {exc}", file=sys.stderr)
            rc = 1
            continue

        if args.output:
            dest = Path(args.output)
        else:
            stem = src.with_suffix("")  # drop .html
            dest = (outdir / (stem.name + LOCKED_SUFFIX)) if outdir \
                else Path(str(src.with_suffix("")) + LOCKED_SUFFIX)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(locked, encoding="utf-8")
        tag = " (one-time view)" if args.one_time else ""
        print(f"locked {src} -> {dest}{tag}")
    return rc


def cmd_unlock(args: argparse.Namespace) -> int:
    src = Path(args.input)
    if not src.is_file():
        print(f"error: no such file: {src}", file=sys.stderr)
        return 2
    try:
        plaintext = unlock(_read_text(src), args.pin)
    except Exception:
        print("error: wrong PIN or not a LockHTML file", file=sys.stderr)
        return 1
    if args.output:
        Path(args.output).write_text(plaintext, encoding="utf-8")
        print(f"unlocked {src} -> {args.output}")
    else:
        sys.stdout.write(plaintext)
    return 0


def _gui_source() -> Path:
    """Return a filesystem path to the bundled GUI page."""
    from importlib import resources
    ref = resources.files("lockhtml").joinpath("gui/index.html")
    if isinstance(ref, Path) or hasattr(ref, "__fspath__"):
        p = Path(str(ref))
        if p.is_file():
            return p
    # Fall back to extracting package data to a temp file.
    data = ref.read_text(encoding="utf-8")
    tmp = Path(tempfile.gettempdir()) / "lockhtml-gui.html"
    tmp.write_text(data, encoding="utf-8")
    return tmp


def cmd_gui(args: argparse.Namespace) -> int:
    page = _gui_source()
    uri = page.as_uri()
    print(f"opening LockHTML GUI: {uri}")
    opened = webbrowser.open(uri)
    if not opened:
        print("Could not open a browser automatically. Open this file manually:")
        print(uri)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lockhtml",
        description="PIN-protect and one-time-view HTML files (AES-256-GCM).",
    )
    parser.add_argument("--version", action="version",
                        version=f"lockhtml {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_lock = sub.add_parser("lock", help="encrypt HTML file(s) behind a PIN")
    p_lock.add_argument("input", nargs="+", help="input .html file(s)")
    p_lock.add_argument("--pin", required=True, help="PIN / passphrase")
    p_lock.add_argument("-o", "--output", help="output path (single input only)")
    p_lock.add_argument("--outdir", help="directory to write locked files into")
    p_lock.add_argument("--one-time", action="store_true",
                        help="expire the document after the first view")
    p_lock.add_argument("--iterations", type=int, default=250_000,
                        help="PBKDF2 iterations (default: 250000)")
    p_lock.set_defaults(func=cmd_lock)

    p_unlock = sub.add_parser("unlock", help="decrypt a locked HTML file with its PIN")
    p_unlock.add_argument("input", help="locked .html file")
    p_unlock.add_argument("--pin", required=True, help="PIN / passphrase")
    p_unlock.add_argument("-o", "--output", help="write plaintext here (default: stdout)")
    p_unlock.set_defaults(func=cmd_unlock)

    p_gui = sub.add_parser("gui", help="open the browser-based graphical interface")
    p_gui.set_defaults(func=cmd_gui)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
