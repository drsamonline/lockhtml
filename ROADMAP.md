# Roadmap

LockHTML deliberately stays **server-free**: every feature must work offline, in the browser, with
no backend. This file tracks what is shipped and what is planned.

Legend: ✅ shipped · 🔜 planned · 💭 under consideration

## Shipped in v1.1

- ✅ Argon2id key derivation (default) with PBKDF2-SHA256 fallback
- ✅ Keyfile second factor (HMAC pepper)
- ✅ Ed25519 signing and in-browser verification
- ✅ Duress PIN with a decoy document
- ✅ View limits: one-time, max views, not-before, expiry
- ✅ Watermarking
- ✅ Any file type (HTML renders; others download)
- ✅ Localised viewer (English, Hindi, Gujarati)
- ✅ PWA / offline GUI, passphrase generator
- ✅ Payload format v2 with a written spec
- ✅ Build-time minification with verification

## Shipped in v2.0

- ✅ **Hidden volume** — several PIN slots in one file, each opening different content
- ✅ **Auto-calibrated KDF** — `calibrate` + `--auto-kdf`
- ✅ **Streaming decoy** — the duress PIN now works on streaming containers
- ✅ **Folder support** — `--recursive` (CLI) and folder pick/drop (GUI)
- ✅ **Constant-memory save** — decrypt a stream straight to disk (File System Access API)
- ✅ **Launcher scripts** — `.sh` / `.bat` for the CLI and the GUI, plus `requirements.txt`

## Shipped in v1.4

- ✅ **Shamir secret sharing** — split the key so any *k* of *n* holders can open it
- ✅ `.shares.txt` distribution, `--shares` / `--share`, embedded + streaming
- ✅ Shares combinable with a PIN and a keyfile
- ✅ GF(256) Shamir implemented in both Python and JavaScript

## Shipped in v1.3

- ✅ **X25519 recipient mode** — lock to a public key, no shared secret (embedded + streaming)
- ✅ Optional PIN layered on top of the recipient key
- ✅ `keygen --type x25519`, `lock --to`, `unlock --key`
- ✅ GUI recipient field and private-key prompt

## Shipped in v1.2

- ✅ **Streaming container** for very large files (chunked AES-GCM, O(chunk) memory)
- ✅ Whole-file integrity MAC binding chunk order, count, size and metadata
- ✅ GUI create/open for streaming bundles
- ✅ `docs/DESIGN.md` design notes on size limits and containers
- ✅ Headless-browser end-to-end tests committed to the repo

## Planned

### 🔜 Cryptography
- **`age` interoperability** — read and write [age](https://age-encryption.org) v1 files (X25519 and
  scrypt recipients). *Deferred from v2.0 deliberately:* it is a separate file format with its own
  chunked-ChaCha20-Poly1305 STREAM construction, and `cryptography`'s ChaCha20-Poly1305 has no Web
  Crypto equivalent — so it would be CLI-only, and it needs validating against the official age test
  vectors before it can be trusted. Shipping unverified crypto interop is worse than not shipping it.
  This stays the top cryptography item.
- **Hidden slots in recipient mode** — hidden content without a PIN.

### 🔜 Usability
- **Constant-memory output in the GUI** — the viewer has it; the GUI's unlock tab still assembles a Blob.
- **More languages** for the viewer and the GUI.
- **QR code for the PIN** generated offline.
- **Reduced-motion and high-contrast modes.**

### 🔜 Distribution
- **Browser extension** (Chrome / Firefox) — right-click a page to lock it, offline.
- **Tauri desktop wrapper** — a native window using the OS webview (still no server).
- **PyPI publication** so `pip install lockhtml` works without the git URL. The packaging is ready
  (`python -m build` produces a wheel and sdist), and a `publish.yml` workflow is included that uses
  PyPI **trusted publishing** — it just needs a publisher configured on the PyPI side, which requires
  account access this project does not have from CI.

### 💭 Under consideration
- WebAuthn / passkey as an unlock factor.
- Detached signature files (`.sig`) alongside a locked file.
- A signed "release manifest" so the GUI can verify its own assets.

## Not planned

- Any server-side component, one-time links, or telemetry.
- Anything that requires uploading a file.
