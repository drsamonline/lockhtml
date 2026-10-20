# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Instead, report them
privately via GitHub's [security advisories](https://github.com/drsamonline/lockhtml/security/advisories/new)
or by email to **sohilmomin2000@gmail.com**.

Include a description, steps to reproduce, and the impact you believe it has.
We aim to acknowledge reports within a few days.

## Scope and design intent

LockHTML is a **client-side** tool. Understanding its threat model matters:

- The PIN provides real confidentiality: the document is encrypted with AES-256-GCM
  and the key is derived with PBKDF2-SHA256. Without the PIN the content is unreadable,
  even from the raw source.
- **One-time view is best-effort.** Expiry is enforced in the browser via `localStorage`.
  A recipient who controls their machine can defeat it (copy the file, use another
  browser/profile, clear storage, or screenshot the decrypted page). This is a known and
  documented limitation, not a vulnerability.
- The tool is **not** designed to resist an adversary who has the PIN, the decrypted
  plaintext, or full control of the recipient's device.

Reports that assume a server-enforced single-view guarantee are out of scope; that
guarantee is not offered.

## Cryptography

- Cipher: AES-256-GCM (authenticated).
- KDF: PBKDF2-HMAC-SHA256, 250,000 iterations by default (configurable).
- Random salt (16 bytes) and IV (12 bytes) per file, from a CSPRNG.
