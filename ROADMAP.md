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
- **Auto-calibrated KDF cost** — measure the device and pick the strongest parameters it can handle
  in a fixed time budget, stored per file.
- **Hidden volume** — a decoy and a real payload in one file with plausible deniability.

### 🔜 Usability
- **Constant-memory output** in the browser via the File System Access API (streaming save),
  so decryption no longer assembles the whole result in a Blob.
- **Decoy PIN support in the streaming container** (currently embedded-only).
- **Folder drop** — lock an entire multi-file site into one bundle.
- **More languages** for the viewer and the GUI.
- **QR code for the PIN** generated offline.
- **Reduced-motion and high-contrast modes.**

### 🔜 Distribution
- **Browser extension** (Chrome / Firefox) — right-click a page to lock it, offline.
- **Tauri desktop wrapper** — a native window using the OS webview (still no server).
- **`age` format interop** — read and write the widely-used `age` container.
- **PyPI publication** so `pip install lockhtml` works without the git URL.

### 💭 Under consideration
- WebAuthn / passkey as an unlock factor.
- Detached signature files (`.sig`) alongside a locked file.
- A signed "release manifest" so the GUI can verify its own assets.

## Not planned

- Any server-side component, one-time links, or telemetry.
- Anything that requires uploading a file.
