# LockHTML file format (v2)

A *locked file* is an ordinary HTML page — the **viewer** — with a JSON **payload** embedded in a
`<script id="payload" type="application/json">` element. The original content never appears in
plaintext.

This document specifies format **v2** (LockHTML ≥ 1.1). v1 files remain readable.

## Payload

```jsonc
{
  "v":         2,
  "kind":      "html" | "file",     // how the viewer should present the plaintext
  "name":      "report.pdf" | null, // original filename (kind == "file")
  "kdf":       "argon2id" | "pbkdf2",
  "kdfparams": { "m": 19456, "t": 2, "p": 1 }   // argon2id  (m in KiB)
               | { "iter": 250000 },            // pbkdf2
  "salt":      "<base64>",          // 16 random bytes
  "iv":        "<base64>",          // 12 random bytes, AES-GCM nonce
  "ct":        "<base64>",          // AES-256-GCM ciphertext || tag
  "id":        "<hex>",             // sha256(ct)[0:8], used as the local view-counter key
  "onetime":   true | false,        // legacy shorthand for maxviews == 1
  "maxviews":  1 | null,            // view limit, null = unlimited
  "notbefore": "2026-01-01T00:00:00+00:00" | null,
  "expires":   "2027-01-01T00:00:00+00:00" | null,
  "watermark": "For A. Sharma" | null,
  "keyfile":   true | false,        // a keyfile is required in addition to the PIN
  "sig":       { "alg": "Ed25519", "pub": "<base64>", "val": "<base64>" } | null,
  "decoy":     { "kdf": ..., "kdfparams": ..., "salt": ..., "iv": ..., "ct": ... } | null
}
```

All binary fields are standard base64. Timestamps are ISO 8601 with a UTC offset.

## Key derivation

Given the PIN as UTF-8 bytes and the optional keyfile bytes:

1. **Derive a 256-bit key** from the PIN and the per-file salt:
   - `argon2id`: Argon2id with the given `m`/`t`/`p`, `hash_len = 32`.
   - `pbkdf2`  : PBKDF2-HMAC-SHA256 with `iter` iterations, 32-byte output.
2. **If a keyfile is present**, mix it in as a pepper:

   ```
   key = HMAC-SHA256(key = derived, message = keyfile_bytes)
   ```

   The keyfile is *not* concatenated to the PIN — this avoids length-extension style ambiguities and
   keeps the two KDFs identical. The result is the AES-256-GCM key.

The keyfile is never stored in the file; only the boolean `keyfile` flag is.

## Encryption

`ct = AES-256-GCM(key, iv, plaintext)` with the 12-byte `iv` as the nonce and no additional
authenticated data. A fresh random salt and IV are generated for every file, so a key is used for
exactly one message.

## Signature (optional)

When signing, the **ciphertext** is signed:

- `pub` — the signer's Ed25519 public key, 32 raw bytes, base64.
- `val` — the 64-byte Ed25519 signature over the raw ciphertext bytes, base64.

The viewer verifies the signature **before** attempting decryption. If verification fails, the file
is not opened. If the browser does not support Ed25519, the viewer warns and proceeds.

## Decoy (optional)

`decoy` holds an independently encrypted payload with its **own** salt and IV, the same KDF and the
same keyfile requirement. The viewer first tries the main ciphertext; if authentication fails it
tries the decoy. A PIN that opens the decoy reveals only the decoy content.

## Viewer behaviour

1. Read the payload; localise the UI.
2. If `notbefore` is in the future, or `expires` has passed, refuse to open.
3. If `maxviews` is set and the local counter (`idb`/`localStorage`, key `lockhtml_v2_<id>`) is
   `>= maxviews`, refuse to open.
4. If `sig` is present, verify it; block on failure.
5. Read the keyfile if `keyfile` is true.
6. Derive the key, decrypt, and:
   - `kind == "html"` → render in a sandboxed `<iframe srcdoc>`.
   - `kind == "file"` → offer the decrypted bytes as a download.
7. Increment the view counter (unless the decoy was used).
8. Show the watermark overlay if set.

The viewer's iframe is sandboxed **without** `allow-same-origin`, so a decrypted document cannot
reach the viewer's own storage.

## v1 compatibility

Version 1 payloads used `"kdf": "PBKDF2-SHA256"` with a top-level `"iter"` and no other fields.
Readers must treat a missing `kdfparams` as `{ "iter": payload.iter }`. v1 had no keyfile, signing,
limits, watermark or decoy.

## Compatibility contract

The Python core (`lockhtml/core.py`) and the JavaScript implementations (the viewer and the GUI)
must produce and consume byte-identical payloads. This is enforced in CI by locking a file with the
JavaScript code path and decrypting it with the Python CLI, and vice versa.
