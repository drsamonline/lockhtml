# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2026-10-20

A post-release audit pass. Every item below is a fix found by *running* things rather than reading
them — see `docs/AUDIT.md` for the detail.

### Fixed
- **`gui.sh` did not work at all.** It `exec`'d `lockhtml.sh`, which has no executable bit, so it died
  with `Permission denied`. It now runs the launcher through `sh`.
- **The GUI's Lock button stayed disabled** when you used a recipient public key or a share split
  instead of a PIN: only the PIN field had an input listener, so the button never re-evaluated.
- **The GUI silently ignored a hidden volume** combined with recipient or split mode, which could
  leave you believing a hidden payload existed when it did not. It is now an explicit error, matching
  the CLI.
- **`lockhtml.bat` broke on any Python path containing a space** (`C:\Program Files\…`): `%PY%` was
  used unquoted. It is quoted at every use site now.
- **`unlock()`/`decrypt()` on a streaming payload** raised a bare `KeyError`; they now explain that a
  streaming container needs its sidecar.

### Changed
- `--auto-kdf` now says so instead of silently doing nothing when `--kdf pbkdf2` is also given, and
  mismatched `--hidden-pin`/`--hidden-file` counts print a note.
- **`make minify` is now an alias for `make build`.** Minifying an already-minified `index.html` is
  not idempotent, so the old target could leave an asset that CI rejects with a confusing diff.

### Tests
- The launcher test now *executes* `lockhtml.sh` (lock + unlock a real file) and `gui.sh` instead of
  only syntax-checking them — a syntax check is exactly what missed the `gui.sh` bug.
- The browser suite no longer waits the full 25 s stage timeout for checks that *expect* a rejection;
  it resolves as soon as the viewer shows an error. Ten negative checks were burning ~250 s between
  them, which had pushed the suite past the CI runner's patience. It now finishes in about 40 s.
- The browser fixtures use cheap-but-real Argon2id parameters: the suite unlocks dozens of files in a
  row, and full-strength parameters in WASM made it needlessly slow. Production-strength parameters
  remain covered by the Python unit tests.

## [2.0.0] - 2026-10-20

### Added
- **Hidden volume** — a second (or third…) PIN that opens entirely different content, so the file has
  a plausible cover story. `lock --hidden-pin PIN --hidden-file FILE` (repeatable).
- **Auto-calibrated KDF** — `calibrate` measures the machine and `--auto-kdf` uses the strongest
  Argon2id time cost that still unlocks in a sensible time; the parameters travel in the file.
- **Streaming decoy** — a duress PIN now works on streaming containers too: it opens a small embedded
  page instead of decrypting the sidecar.
- **Folder support** — `lock --recursive DIR` (CLI) and a folder picker / directory drop in the GUI.
- **Constant-memory save** — the viewer can decrypt a streaming container straight to disk, chunk by
  chunk, using the File System Access API (Chromium); other browsers keep the Blob download.
- **Launcher scripts** — `lockhtml.sh` / `lockhtml.bat` and `gui.sh` / `gui.bat`, plus
  `requirements.txt`, so the tool runs from a checkout with no install step.
- `decrypt_any()` in the core, which reports whether the main payload, a hidden slot or the decoy
  opened.

### Changed
- The viewer and core now try the main payload, then every hidden slot, then the decoy.
- The streaming MAC also covers the decoy blob when one is present (older sidecars still verify).
- Streaming encryption was factored into `_stream_write` so all key modes share one code path.

### Fixed
- The browser end-to-end harness now recycles the page (and relaunches Chrome if it dies) so a long
  run in a memory-tight container cannot fail spuriously.

### Notes
- `age` interop is **not** in this release — see [ROADMAP.md](ROADMAP.md) for why and what is planned.

## [1.4.0] - 2026-10-20

### Added
- **Shamir secret sharing** — split a file's key into *n* shares so that any *k* of them (and no
  fewer) can open it. `lock --shares 5:3` writes a `.shares.txt` file to distribute separately.
- `unlock --shares <file>` (one share per line) or `--share <b64>` (repeatable).
- Shares mode works in the **streaming container** and can be combined with a PIN and a keyfile.
- GUI support: a share-split field on the lock tab and a shares box on unlock.
- GF(256) arithmetic and Shamir split/combine implemented identically in Python and JavaScript.

### Changed
- Streaming encryption was factored into `_stream_write`, shared by the PIN, recipient and shares
  paths.
- `docs/FORMAT.md` now specifies shares mode and its share encoding.

### Security
- The share count and threshold are covered by the streaming MAC, so they cannot be tampered with.
- Reconstruction rejects duplicate indices, index 0, and ragged share lengths; extra shares beyond
  the threshold are ignored rather than trusted.
- The decoy PIN and recipient mode cannot be combined with shares.

## [1.3.0] - 2026-10-20

### Added
- **X25519 recipient mode** — lock a file to someone's public key so only they can open it, with no
  shared secret. `keygen --type x25519` produces a private key (`.pem`) and a public key (`.pub`).
- `lock --to <public key>` to lock to a recipient, and `unlock --key <private key>` to open one.
- An optional **PIN layered on top** of the recipient key (two factors), and the usual optional
  keyfile pepper.
- Recipient mode works in the **streaming container** as well, so large files can be sent to a
  specific person.
- GUI support: a recipient public-key field on the lock tab, and a private-key prompt on unlock.

### Changed
- `encrypt`, `decrypt`, `unlock`, `build_locked_html`, `stream_encrypt_file` and
  `stream_decrypt_file` take `pin=None` plus a `recipient` / `private_key` argument.
- `--pin` is no longer required on `lock`/`unlock` (a recipient key can replace it).
- The streaming MAC now also covers the ephemeral key in recipient mode (PIN-mode sidecars are
  unchanged, so v1.2 files still verify).

### Security
- Hybrid encryption with a fresh ephemeral keypair per file; HKDF-SHA256 over the shared secret.
- The decoy PIN is rejected in recipient mode rather than silently ignored.

## [1.2.0] - 2026-10-20

### Added
- **Streaming container** (`--stream`) for large files: the ciphertext is written to a sidecar
  `.bin` in fixed-size chunks, so reading and decryption cost ~O(chunk size) instead of O(file
  size). Supports multi-gigabyte files; the recipient gets two files.
- `--chunk-size` (KiB) to tune the chunk size.
- `unlock --data` to point at the sidecar when opening a streaming bundle.
- Per-chunk nonces derived from a base IV plus the chunk index, with the index bound as
  Additional Authenticated Data (the STREAM construction), plus a whole-file HMAC over the
  metadata and every chunk tag.
- GUI support for creating and opening streaming bundles.
- `docs/DESIGN.md` — design notes explaining the size limits and the two containers.
- Headless-browser end-to-end tests in the repo (`tools/e2e_browser.mjs`,
  `tools/e2e_gui.mjs`), covering both containers.

### Changed
- `docs/FORMAT.md` now specifies the streaming container.

### Security
- The streaming MAC binds chunk order, count, size, KDF parameters and limits, so truncation,
  reordering and metadata tampering are all detected.

## [1.1.0] - 2026-10-20

### Added
- **Argon2id** key derivation (memory-hard), now the default. PBKDF2-SHA256 remains available.
- **Keyfile** second factor — a pepper mixed into the key after derivation.
- **Ed25519 signing** — `lockhtml keygen` plus `--sign`, verified in the browser before display.
- **Duress PIN** — a second PIN that opens a configurable decoy document.
- **View limits** — `--max-views`, `--not-before` and `--expires`, enforced client-side.
- **Watermarking** — `--watermark` overlays recipient-specific text on the decrypted view.
- **Any file type** — non-HTML payloads are offered as a download rather than rendered.
- **Localised viewer** — English, Hindi and Gujarati unlock screens.
- **PWA** — the hosted GUI is installable and cached for offline use.
- **Passphrase generator** in the GUI.
- Payload **format v2** (see [docs/FORMAT.md](docs/FORMAT.md)); v1 files remain readable.
- `docs/FORMAT.md` (format specification), `docs/AUDIT.md` (self-audit), `ROADMAP.md`.
- Minified, build-verified generated assets (viewer template ~34% smaller).

### Changed
- `unlock()` now returns raw bytes rather than text, to support binary payloads.
- The viewer is built in two variants: a small PBKDF2-only viewer and an Argon2-capable one,
  so PBKDF2-locked files stay small.
- Generated assets are now built by `tools/build.py` and minified by `tools/minify.mjs`
  (replacing `tools/build_gui.py`).

### Security
- Keyfile material is mixed with an HMAC-SHA256 pepper rather than concatenated, avoiding
  length-extension style ambiguities.
- Signature verification failure now blocks opening.

## [1.0.0] - 2026-10-20

### Added
- Initial release: `lockhtml lock`, `lockhtml unlock`, `lockhtml gui`.
- AES-256-GCM with PBKDF2-SHA256 key derivation.
- Best-effort one-time view.
- Cross-platform CLI and a single-file browser GUI.
- GitHub Actions CI (Linux/Windows/macOS, Python 3.9–3.12) and GitHub Pages deployment.

[2.0.1]: https://github.com/drsamonline/lockhtml/releases/tag/v2.0.1
[2.0.0]: https://github.com/drsamonline/lockhtml/releases/tag/v2.0.0
[1.4.0]: https://github.com/drsamonline/lockhtml/releases/tag/v1.4.0
[1.3.0]: https://github.com/drsamonline/lockhtml/releases/tag/v1.3.0
[1.1.0]: https://github.com/drsamonline/lockhtml/releases/tag/v1.1.0
[1.0.0]: https://github.com/drsamonline/lockhtml/releases/tag/v1.0.0
