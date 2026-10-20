"""Command-line interface for LockHTML."""

from __future__ import annotations

import argparse
import base64
import sys
import tempfile
import webbrowser
from pathlib import Path

from . import __version__
from .core import (
    ARGON2_PARAMS,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_KDF,
    DEFAULT_KDF_SECONDS,
    build_locked_html,
    build_shared_html,
    calibrate_argon2,
    extract_payload,
    generate_recipient_key,
    generate_signing_key,
    load_recipient_key,
    load_signing_key,
    parse_recipient_public,
    recipient_public_bytes,
    render_viewer,
    save_recipient_key,
    save_signing_key,
    stream_decrypt_file,
    stream_encrypt_file,
    stream_encrypt_shares_file,
    try_decoy,
    unlock,
)

LOCKED_SUFFIX = ".locked.html"
HIDDEN_HTML = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Document</title></head>"
    "<body style='font-family:system-ui;max-width:640px;margin:60px auto;color:#222'>"
    "<h2>Nothing here</h2><p>This document contains nothing further.</p></body></html>"
)
DECOY_HTML = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Document</title></head>"
    "<body style='font-family:system-ui;max-width:640px;margin:60px auto;color:#222'>"
    "<h2>No content</h2><p>This document contains nothing further.</p></body></html>"
)


def _read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def cmd_lock(args: argparse.Namespace) -> int:
    inputs: list = []
    for raw in args.input:
        p = Path(raw)
        if p.is_dir():
            if not args.recursive:
                print(f"error: {p} is a directory (pass --recursive to lock the files inside)",
                      file=sys.stderr)
                return 2
            inputs.extend(sorted(x for x in p.rglob("*") if x.is_file()))
        else:
            inputs.append(p)
    if not inputs:
        print("error: nothing to lock", file=sys.stderr)
        return 2
    missing = [p for p in inputs if not p.is_file()]
    if missing:
        for p in missing:
            print(f"error: no such file: {p}", file=sys.stderr)
        return 2
    if args.output and len(inputs) > 1:
        print("error: -o/--output can only be used with a single input file", file=sys.stderr)
        return 2

    keyfile = Path(args.keyfile).read_bytes() if args.keyfile else None
    sign_key = load_signing_key(args.sign) if args.sign else None

    recipient = None
    if args.to:
        src = Path(args.to)
        recipient = parse_recipient_public(src.read_text(encoding="utf-8") if src.is_file() else args.to)

    share_spec = None
    if args.shares:
        try:
            n_s, k_s = args.shares.lower().replace("of", ":").split(":")
            share_spec = (int(n_s), int(k_s))
        except Exception:
            print("error: --shares must look like N:K (e.g. 5:3)", file=sys.stderr)
            return 2
        if not (1 <= share_spec[1] <= share_spec[0] <= 255):
            print("error: --shares needs 1 <= k <= n <= 255", file=sys.stderr)
            return 2

    if not args.pin and recipient is None and share_spec is None:
        print("error: provide --pin, --to <recipient public key>, or --shares N:K", file=sys.stderr)
        return 2
    if share_spec is not None and recipient is not None:
        print("error: --shares and --to cannot be combined", file=sys.stderr)
        return 2
    if args.decoy_pin and (recipient is not None or share_spec is not None):
        print("error: --decoy-pin is only available in PIN mode", file=sys.stderr)
        return 2

    decoy = None
    if args.decoy_pin:
        decoy_doc = Path(args.decoy_file).read_text(encoding="utf-8") if args.decoy_file else DECOY_HTML
        decoy = (decoy_doc, args.decoy_pin)

    hidden = None
    if args.hidden_pin:
        if args.stream:
            print("error: --hidden-pin is not available with --stream", file=sys.stderr)
            return 2
        if share_spec is not None or recipient is not None:
            print("error: --hidden-pin is only available in PIN mode", file=sys.stderr)
            return 2
        hidden = []
        hfiles = args.hidden_file or []
        for i, hp in enumerate(args.hidden_pin):
            hdata = _read_bytes(Path(hfiles[i])) if i < len(hfiles) else HIDDEN_HTML.encode("utf-8")
            hidden.append((hp, hdata))

    kdfparams = None
    if args.auto_kdf and args.kdf == "argon2id":
        kdfparams = calibrate_argon2(args.kdf_time)
        print(f"auto KDF: argon2id m={kdfparams['m']} KiB, t={kdfparams['t']}, p={kdfparams['p']} "
              f"(~{args.kdf_time:g}s per derivation on this machine)")

    outdir = Path(args.outdir) if args.outdir else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)

    rc = 0
    for src in inputs:
        if args.output:
            dest = Path(args.output)
        else:
            stem = src.with_suffix("")
            dest = (outdir / (stem.name + LOCKED_SUFFIX)) if outdir else Path(str(stem) + LOCKED_SUFFIX)
        dest.parent.mkdir(parents=True, exist_ok=True)

        is_html = src.suffix.lower() in (".html", ".htm")
        kind = "html" if is_html else "file"
        name = None if is_html else src.name

        try:
            if share_spec is not None:
                n, k = share_spec
                common = dict(keyfile=keyfile, one_time=args.one_time, max_views=args.max_views,
                              not_before=args.not_before, expires=args.expires,
                              watermark=args.watermark, kind=kind, name=name, sign_key=sign_key)
                if args.stream:
                    bin_path = dest.with_suffix(".bin")
                    payload, share_strings = stream_encrypt_shares_file(
                        str(src), args.pin, str(bin_path), n=n, k=k,
                        chunk_size=args.chunk_size * 1024, **common)
                    dest.write_text(render_viewer(payload), encoding="utf-8")
                    extra = f" + {bin_path}"
                else:
                    locked, share_strings = build_shared_html(
                        _read_bytes(src), args.pin, n=n, k=k, **common)
                    dest.write_text(locked, encoding="utf-8")
                    extra = ""
                shares_path = Path(str(dest.with_suffix("")) + ".shares.txt")
                shares_path.write_text("\n".join(share_strings) + "\n", encoding="utf-8")
                extra += f" + {shares_path}"
            elif args.stream:
                bin_path = dest.with_suffix(".bin")
                payload = stream_encrypt_file(
                    str(src), args.pin, str(bin_path),
                    recipient=recipient,
                    kdf=args.kdf, kdfparams=kdfparams, keyfile=keyfile,
                    chunk_size=args.chunk_size * 1024,
                    one_time=args.one_time, max_views=args.max_views,
                    not_before=args.not_before, expires=args.expires,
                    watermark=args.watermark, kind=kind, name=name, sign_key=sign_key,
                    decoy=decoy,
                )
                dest.write_text(render_viewer(payload), encoding="utf-8")
                extra = f" + {bin_path}"
            else:
                locked = build_locked_html(
                    _read_bytes(src), args.pin,
                    recipient=recipient,
                    kdf=args.kdf, kdfparams=kdfparams, keyfile=keyfile,
                    one_time=args.one_time,
                    max_views=args.max_views, not_before=args.not_before,
                    expires=args.expires, watermark=args.watermark,
                    kind=kind, name=name, sign_key=sign_key, decoy=decoy, hidden=hidden,
                )
                dest.write_text(locked, encoding="utf-8")
                extra = ""
        except Exception as exc:  # pragma: no cover - defensive
            print(f"error: {src}: {exc}", file=sys.stderr)
            rc = 1
            continue

        tags = []
        if share_spec is not None:
            tags.append(f"shares={share_spec[1]}-of-{share_spec[0]}")
        elif recipient is not None:
            tags.append("recipient")
        else:
            tags.append(args.kdf)
        if args.stream:
            tags.append("streaming")
        if args.one_time or args.max_views:
            tags.append("one-time" if (args.one_time or args.max_views == 1) else f"max-views={args.max_views}")
        if keyfile:
            tags.append("keyfile")
        if sign_key:
            tags.append("signed")
        if decoy and not args.stream:
            tags.append("decoy")
        suffix = ("  [" + ", ".join(tags) + "]") if tags else ""
        print(f"locked {src} -> {dest}{extra}{suffix}")
    return rc


def cmd_unlock(args: argparse.Namespace) -> int:
    src = Path(args.input)
    if not src.is_file():
        print(f"error: no such file: {src}", file=sys.stderr)
        return 2
    keyfile = Path(args.keyfile).read_bytes() if args.keyfile else None
    private_key = load_recipient_key(args.key) if args.key else None
    shares = list(args.share) if args.share else None
    if args.shares:
        share_file = Path(args.shares)
        if not share_file.is_file():
            print(f"error: shares file not found: {share_file}", file=sys.stderr)
            return 2
        shares = [ln.strip() for ln in share_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    text = src.read_text(encoding="utf-8")
    try:
        payload = extract_payload(text)
        if payload.get("container") == "stream":
            duress = try_decoy(payload, args.pin, keyfile)
            if duress is not None:
                plaintext = duress          # the decoy PIN opens the harmless page
            else:
                data_path = Path(args.data) if args.data else src.with_suffix(".bin")
                if not data_path.is_file():
                    print(f"error: streaming data file not found: {data_path}", file=sys.stderr)
                    return 2
                plaintext = stream_decrypt_file(
                    str(data_path), payload, args.pin,
                    str(args.output) if args.output else None, keyfile, private_key, shares)
        else:
            plaintext = unlock(text, args.pin, keyfile, private_key, shares)
    except Exception:
        print("error: wrong PIN, missing keyfile, or not a LockHTML file", file=sys.stderr)
        return 1
    if args.output:
        if plaintext is not None:
            Path(args.output).write_bytes(plaintext)
        print(f"unlocked {src} -> {args.output}")
    else:
        sys.stdout.buffer.write(plaintext)
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    if args.type == "x25519":
        dest = Path(args.output or "lockhtml-recipient-key.pem")
        if dest.exists() and not args.force:
            print(f"error: {dest} already exists (use --force to overwrite)", file=sys.stderr)
            return 2
        key = generate_recipient_key()
        save_recipient_key(key, str(dest))
        pub_path = dest.with_suffix(".pub")
        pub_path.write_text(base64.b64encode(recipient_public_bytes(key)).decode() + "\n",
                            encoding="utf-8")
        print(f"wrote X25519 private key -> {dest}   (keep this secret)")
        print(f"wrote X25519 public key  -> {pub_path}   (give this to senders)")
        print("Senders: lockhtml lock FILE --to " + str(pub_path))
        return 0

    dest = Path(args.output or "lockhtml-signing-key.pem")
    if dest.exists() and not args.force:
        print(f"error: {dest} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    key = generate_signing_key()
    save_signing_key(key, str(dest))
    print(f"wrote Ed25519 signing key -> {dest}")
    print("Keep it secret. Use it with: lockhtml lock FILE --pin PIN --sign " + str(dest))
    return 0


def _gui_source() -> Path:
    from importlib import resources
    ref = resources.files("lockhtml").joinpath("gui/index.html")
    p = Path(str(ref))
    if p.is_file():
        return p
    data = ref.read_text(encoding="utf-8")
    tmp = Path(tempfile.gettempdir()) / "lockhtml-gui.html"
    tmp.write_text(data, encoding="utf-8")
    return tmp


def cmd_calibrate(args: argparse.Namespace) -> int:
    params = calibrate_argon2(args.seconds, memory_kib=args.memory, parallelism=args.parallelism)
    print(f"argon2id for ~{args.seconds:g}s on this machine: "
          f"m={params['m']} KiB, t={params['t']}, p={params['p']}")
    print("Use it with:  lockhtml lock FILE --pin PIN --auto-kdf")
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    page = _gui_source()
    uri = page.as_uri()
    print(f"opening LockHTML GUI: {uri}")
    if not webbrowser.open(uri):
        print("Could not open a browser automatically. Open this file manually:")
        print(uri)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lockhtml",
        description="PIN-protect and one-time-view any file (AES-256-GCM).",
    )
    parser.add_argument("--version", action="version", version=f"lockhtml {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_lock = sub.add_parser("lock", help="encrypt file(s) behind a PIN")
    p_lock.add_argument("input", nargs="+", help="input file(s)")
    p_lock.add_argument("--pin", default=None, help="PIN / passphrase (omit when using --to)")
    p_lock.add_argument("--to", default=None,
                        help="lock to an X25519 recipient public key (a .pub file or base64 string)")
    p_lock.add_argument("-o", "--output", help="output path (single input only)")
    p_lock.add_argument("--outdir", help="directory to write locked files into")
    p_lock.add_argument("--kdf", choices=["argon2id", "pbkdf2"], default=DEFAULT_KDF,
                        help="key derivation function (default: argon2id)")
    p_lock.add_argument("--one-time", action="store_true", help="expire after the first view")
    p_lock.add_argument("--max-views", type=int, default=None, help="expire after N views")
    p_lock.add_argument("--not-before", default=None, help="ISO8601 time before which it will not open")
    p_lock.add_argument("--expires", default=None, help="ISO8601 time after which it will not open")
    p_lock.add_argument("--watermark", default=None, help="watermark text shown over the document")
    p_lock.add_argument("--keyfile", default=None, help="require this keyfile in addition to the PIN")
    p_lock.add_argument("--sign", default=None, help="Ed25519 private key (PEM) to sign the file")
    p_lock.add_argument("--decoy-pin", default=None, help="duress PIN that opens a harmless decoy page")
    p_lock.add_argument("--decoy-file", default=None, help="HTML file to use as the decoy page")
    p_lock.add_argument("--shares", default=None, metavar="N:K",
                        help="split the key into N shares, any K of which open the file")
    p_lock.add_argument("--hidden-pin", action="append", default=None, metavar="PIN",
                        help="hide another payload behind a second PIN (repeatable)")
    p_lock.add_argument("--hidden-file", action="append", default=None, metavar="FILE",
                        help="content for the corresponding --hidden-pin")
    p_lock.add_argument("--auto-kdf", action="store_true",
                        help="measure this machine and pick the strongest Argon2id cost")
    p_lock.add_argument("--kdf-time", type=float, default=DEFAULT_KDF_SECONDS, metavar="SECONDS",
                        help="target seconds per derivation for --auto-kdf (default 0.5)")
    p_lock.add_argument("-r", "--recursive", action="store_true",
                        help="recurse into directories given as input")
    p_lock.add_argument("--stream", action="store_true",
                        help="streaming container: write ciphertext to a sidecar .bin (for large files)")
    p_lock.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE // 1024,
                        help="streaming chunk size in KiB (default: 1024)")
    p_lock.set_defaults(func=cmd_lock)

    p_unlock = sub.add_parser("unlock", help="decrypt a locked file with its PIN")
    p_unlock.add_argument("input", help="locked .html file")
    p_unlock.add_argument("--pin", default=None, help="PIN / passphrase")
    p_unlock.add_argument("--key", default=None, help="X25519 private key (PEM) for recipient-mode files")
    p_unlock.add_argument("--keyfile", default=None, help="keyfile, if one is required")
    p_unlock.add_argument("--data", default=None, help="sidecar .bin for a streaming container")
    p_unlock.add_argument("--shares", default=None, metavar="FILE",
                          help="file with one key share per line")
    p_unlock.add_argument("--share", action="append", default=None, metavar="B64",
                          help="a single key share (repeatable)")
    p_unlock.add_argument("-o", "--output", help="write plaintext here (default: stdout)")
    p_unlock.set_defaults(func=cmd_unlock)

    p_keygen = sub.add_parser("keygen", help="generate an Ed25519 signing key or an X25519 recipient key")
    p_keygen.add_argument("--type", choices=["ed25519", "x25519"], default="ed25519",
                          help="ed25519 for signing (default), x25519 for recipient encryption")
    p_keygen.add_argument("-o", "--output", help="output PEM path")
    p_keygen.add_argument("--force", action="store_true", help="overwrite an existing key")
    p_keygen.set_defaults(func=cmd_keygen)

    p_cal = sub.add_parser("calibrate", help="measure this machine and suggest Argon2id parameters")
    p_cal.add_argument("--seconds", type=float, default=DEFAULT_KDF_SECONDS,
                       help="target seconds per derivation (default 0.5)")
    p_cal.add_argument("--memory", type=int, default=ARGON2_PARAMS["m"],
                       help="Argon2id memory cost in KiB")
    p_cal.add_argument("--parallelism", type=int, default=1, help="Argon2id parallelism")
    p_cal.set_defaults(func=cmd_calibrate)

    p_gui = sub.add_parser("gui", help="open the browser-based graphical interface")
    p_gui.set_defaults(func=cmd_gui)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
