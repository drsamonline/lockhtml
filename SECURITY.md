# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Instead, report them
privately via GitHub's [security advisories](https://github.com/drsamonline/lockhtml/security/advisories/new)
or by email to **sohilmomin2000@gmail.com**.

Include a description, steps to reproduce, and the impact you believe it has.
We aim to acknowledge reports within a few days.

## Cryptography (v1.1, format v2)

- Cipher: **AES-256-GCM** (authenticated).
- KDF: **Argon2id** (default) or **PBKDF2-HMAC-SHA256** (optional, lighter).
  - Argon2id parameters: m = 19456 KiB, t = 2, p = 1.
  - PBKDF2 iterations: 250,000.
- Random salt (16 bytes) and IV (12 bytes) per file, from a CSPRNG.
- **Keyfile**: optional; mixed in as `HMAC-SHA256(derived_key, keyfile_bytes)`.
- **Recipient mode**: X25519 hybrid encryption — a fresh ephemeral keypair per file, shared secret
  fed to HKDF-SHA256 (info `lockhtml/x25519`), then AES-256-GCM. An optional PIN extends the HKDF
  input; a keyfile pepper is applied on top. No slow KDF is used, since the ECDH secret is already
  256 bits of entropy. See [docs/FORMAT.md](docs/FORMAT.md#recipient-mode-x25519).
- **Shares mode**: the 32-byte key seed is split with Shamir's scheme over GF(256) (polynomial
  `0x11b`); the key is `HKDF-SHA256(seed || pin, salt, info="lockhtml/shamir")` with an optional
  keyfile pepper. Shares are distributed separately and never stored in the locked file. See
  [docs/FORMAT.md](docs/FORMAT.md#shares-mode-shamir).
- **Hidden volume**: additional payloads ("slots") encrypted under their own PINs, each with its own
  salt and IV, exactly like the main payload. `decrypt_any` tries the main payload, then every slot,
  then the decoy.
- **age interop**: the CLI can read and write age v1 files (X25519 recipients). This is a
  from-scratch implementation of a published format; it is verified against the reference
  implementation but has **not** had an independent security review. See
  [docs/AGE.md](docs/AGE.md).
- **Signing**: optional Ed25519 over the ciphertext (embedded) or over the MAC input (streaming);
  verified in-browser before display.
- **Streaming container**: AES-256-GCM per 1 MiB chunk, nonce = `base_iv || uint32_be(index)`,
  chunk index bound as Additional Authenticated Data, and a whole-file HMAC-SHA256 over the
  metadata and all chunk tags. This detects reordering, duplication, truncation and metadata
  tampering. See [docs/FORMAT.md](docs/FORMAT.md#streaming-container).

Full details are in [`docs/FORMAT.md`](docs/FORMAT.md). A self-audit is recorded in
[`docs/AUDIT.md`](docs/AUDIT.md) — note that this is a *self*-review, not an independent audit.

## Scope and design intent

LockHTML is a **client-side** tool. Understanding its threat model matters:

- The PIN provides real confidentiality: the document is encrypted with AES-256-GCM and the key is
  derived with Argon2id. Without the PIN (and keyfile, if used) the content is unreadable, even from
  the raw source.
- **The streaming container's MAC is keyed by the PIN-derived key**, so it protects integrity but
  not authenticity — only an Ed25519 signature proves who produced the file. Sign when that matters.
- **A hidden volume is plausible deniability, not proof of absence.** The extra slots are visible in
  the file's JSON to anyone who looks — they simply cannot be decrypted without their PIN. It
  protects against someone being *shown* the cover content, not against a forensic look at the file.
- **Shares move the secret, not the trust.** *k-1* shares reveal nothing about the seed, but any *k*
  holders can reconstruct it, and a reconstructed seed cannot be revoked — re-lock the file with a
  fresh split if shares are exposed.
- **Recipient mode moves the secret, not the trust.** Whoever holds the private key can open every
  file locked to it, and a leaked private key cannot be revoked. Rotate keys if one is exposed.
- **View limits, expiry, watermarking and one-time view are best-effort.** Enforcement happens in
  the browser (IndexedDB). A recipient who controls their machine can defeat it — copy the file, use
  another browser/profile, clear storage, or screenshot the decrypted page. This is a known and
  documented limitation, not a vulnerability.
- The tool is **not** designed to resist an adversary who has the PIN, the decrypted plaintext, or
  full control of the recipient's device.

Reports that assume a server-enforced single-view guarantee are out of scope; that guarantee is not
offered.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.1.x | ✅ |
| 1.0.x | ⚠️ security fixes only |
