# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.0]: https://github.com/drsamonline/lockhtml/releases/tag/v1.1.0
[1.0.0]: https://github.com/drsamonline/lockhtml/releases/tag/v1.0.0
