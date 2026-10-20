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
  "mode":      "pin" | "recipient" | "shares",  // see below
  "kdf":       "argon2id" | "pbkdf2" | "x25519-hkdf" | "shamir-hkdf",
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
  "decoy":     { "kdf": ..., "kdfparams": ..., "salt": ..., "iv": ..., "ct": ... } | null,

  // streaming container only (see below); absent or "embedded" otherwise
  "container": "stream",
  "data":      "report.locked.bin",  // sidecar filename
  "baseiv":    "<base64>",           // 8 random bytes
  "chunkSize": 1048576,
  "chunkCount": 12,
  "metamac":   "<base64>"            // HMAC-SHA256 over mac_input
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

## Recipient mode (X25519)

Instead of (or in addition to) a PIN, a file can be locked to a recipient's **X25519 public key**,
so only the holder of the matching private key can open it. No shared secret is exchanged.

The payload carries:

```jsonc
  "mode":      "recipient",
  "kdf":       "x25519-hkdf",
  "kdfparams": { "info": "lockhtml/x25519" },
  "eph":       "<base64 32-byte ephemeral public key>",
  "pin":       true | false,   // whether a PIN is *also* required
  "salt":      "<base64>"      // HKDF salt, 16 random bytes
```

Derivation (hybrid encryption):

```
shared = X25519(ephemeral_private, recipient_public)      # sender
       = X25519(recipient_private, ephemeral_public)      # recipient

ikm = shared || utf8(pin)          # the pin part only when "pin" is true
key = HKDF-SHA256(ikm, salt, info="lockhtml/x25519", 32)
key = HMAC-SHA256(key, keyfile)    # only when a keyfile is required
```

A fresh ephemeral keypair is generated for every file, so the same recipient key can be reused
safely. Because the shared secret is already 256 bits of entropy, no slow KDF is applied on top;
the optional PIN simply extends the HKDF input. `decoy` is not available in recipient mode.

Private keys are PKCS#8 PEM; public keys are the 32-byte raw value, base64.

## Hidden slots (v2.0)

A PIN-mode payload may carry extra payloads in a `slots` array, each encrypted under its own PIN:

```jsonc
  "slots": [ { "kdf": ..., "kdfparams": {...}, "salt": "<b64>", "iv": "<b64>", "ct": "<b64>" } ]
```

Readers try the main payload first, then each slot, then `decoy`. Each slot uses its own salt and IV.
In the streaming container a decoy is stored as a single embedded `decoy` blob (the same shape as the
embedded container's) and its ciphertext is covered by the streaming MAC.

## Auto-calibrated KDF (v2.0)

The `kdfparams` for argon2id are not fixed: `lockhtml calibrate` times one pass on the current machine
and scales the time cost `t` so a derivation takes about `--seconds` (default 0.5). `--auto-kdf`
stores those parameters in the file, so a locked file always opens at the cost it was created with.

## Shares mode (Shamir)

The key can be split between several holders, so that any *k* of *n* of them (and no fewer) can open
the file. The payload carries only the parameters — never the shares themselves:

```jsonc
  "mode":      "shares",
  "kdf":       "shamir-hkdf",
  "kdfparams": { "info": "lockhtml/shamir", "n": 5, "k": 3 },
  "pin":       true | false,   // whether a PIN is *also* required
  "salt":      "<base64>"      // HKDF salt, 16 random bytes
```

A random 32-byte **seed** is generated per file and split with Shamir's scheme over **GF(256)**
(primitive polynomial `0x11b`):

```
key = HKDF-SHA256(seed || utf8(pin), salt, info="lockhtml/shamir", 32)
key = HMAC-SHA256(key, keyfile)      # only when a keyfile is required
```

### Share encoding

A share is `base64(bytes([x]) + y)` where `x` is the share index (1..n) and `y` is the share value
(one byte per seed byte, so 33 bytes for a 32-byte seed). A `.shares.txt` file holds one share per
line. Shares are distributed **separately** from the locked file; the file alone cannot be opened.

### Reconstruction

Given at least `k` shares, the seed is recovered by Lagrange interpolation at `x = 0`:

```
L_i(0) = prod_{m != i} x_m / (x_i - x_m)      # all arithmetic in GF(256)
seed   = XOR_i  y_i * L_i(0)
```

Readers must reject duplicate indices, index 0, and ragged share lengths. Extra shares beyond `k`
are ignored (only the first `k` are used), so a wrong extra share cannot silently corrupt a valid
set.

### Notes

- `k = 1` degenerates to "any single holder", and `k = n` requires everyone.
- The `n` and `k` values are covered by the streaming MAC, so they cannot be tampered with in stream
  mode.
- Shares mode is mutually exclusive with recipient mode, and the decoy PIN is not available.

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

## Streaming container

For large files the ciphertext is not embedded. Instead it goes into a sidecar file named by
`data`, and the payload carries `container: "stream"` plus the chunking parameters. The sidecar is:

```
"LKHS1" (5 bytes) || chunk_0 || chunk_1 || ... || chunk_{n-1}
```

Each chunk is `AES-256-GCM(plaintext, nonce, aad) = ciphertext || 16-byte tag`, where for chunk `i`:

```
nonce = base_iv (8 bytes, base64-decoded from "baseiv") || uint32_be(i)
aad   = uint32_be(i)
```

Every chunk but the last has `chunkSize` plaintext bytes; the last holds the remainder. There is no
base64, so the sidecar is about 16 bytes per chunk larger than the original file.

### Whole-file integrity

A MAC binds the metadata and every chunk tag together, so chunks cannot be reordered, duplicated,
truncated or extended, and the metadata cannot be tampered with:

```
meta_string = join("|", [
    "v2", kdf, kdfparams_str, chunkSize, chunkCount, kind, name or "",
    salt, baseiv, maxviews or "", notbefore or "", expires or ""
])

mac_input = utf8(meta_string) || tag_0 || tag_1 || ... || tag_{n-1}
metamac   = HMAC-SHA256(key, mac_input)
signature = Ed25519(mac_input)          # optional, when signed
```

where `kdfparams_str` is `"m,t,p"` for Argon2id and `"iter"` for PBKDF2. The reader must recompute
`mac_input` exactly and compare `metamac` in constant time before returning any plaintext.

### Reader behaviour

1. Read and check the 5-byte magic.
2. For each chunk index, read exactly `chunkSize + 16` bytes (all remaining bytes for the last),
   decrypt with the derived nonce and AAD, and keep only the 16-byte tag.
3. Reject trailing bytes after the last chunk.
4. Verify `metamac`, then the signature if present.

The sidecar is read lazily (in the browser via `File.slice`), so reading and decryption are
`O(chunkSize)`; see [DESIGN.md](DESIGN.md) for the memory discussion.

## Compatibility contract

The Python core (`lockhtml/core.py`) and the JavaScript implementations (the viewer and the GUI)
must produce and consume byte-identical payloads, including the GF(256) arithmetic used for shares. This is enforced in CI by locking a file with the
JavaScript code path and decrypting it with the Python CLI, and vice versa, and by a headless-browser
end-to-end test covering both containers (`tools/e2e_browser.mjs`).
