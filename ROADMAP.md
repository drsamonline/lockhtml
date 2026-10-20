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

## Planned

### 🔜 Cryptography
- **Shamir secret sharing** — split the unlock key so *k* of *n* holders must combine.
- **X25519 public-key mode** — lock to a recipient's public key, no shared secret. Web Crypto
  exposes X25519 natively in current browsers, so no WASM is needed.
- **Auto-calibrated KDF cost** — measure the device and pick the strongest parameters it can handle
  in a fixed time budget, stored per file.
- **Hidden volume** — a decoy and a real payload in one file with plausible deniability.

### 🔜 Usability
- **Streaming / chunked encryption** for very large files without exhausting memory.
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
