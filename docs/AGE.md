# age interoperability

LockHTML can read and write [age](https://age-encryption.org/v1) files, the format used by the
`age` tool and by a growing number of other programs. This means an age file sent to you can be
opened with `lockhtml age-decrypt`, and a file you lock with `lockhtml age-encrypt` can be opened
with `age`.

## What is supported

| Feature | Status |
| --- | --- |
| age v1 header, header MAC | ✅ |
| `X25519` recipients and identities (Bech32 `age1…` / `AGE-SECRET-KEY-1…`) | ✅ |
| STREAM payload (64 KiB ChaCha20-Poly1305 chunks) | ✅ |
| Multiple recipients per file | ✅ |
| Unknown stanza types | ✅ skipped on decrypt, as the spec requires |
| `scrypt` passphrase recipients | ❌ not implemented |
| ML-KEM / X-Wing hybrid recipients | ❌ not implemented |
| P-256 tagged recipients | ❌ not implemented |
| ASCII armor (`-----BEGIN AGE ENCRYPTED FILE-----`) | ❌ not implemented |

An age file that also carries a stanza type we do not implement still opens, as long as one of its
`X25519` stanzas matches your identity.

## Usage

```bash
lockhtml keygen --type age -o key.txt        # writes an age identity + prints the recipient
lockhtml age-encrypt report.pdf -r age1abc…  # -> report.pdf.age
lockhtml age-decrypt report.pdf.age -i key.txt -o report.pdf
```

`-r` / `-i` are repeatable, and `-R recipients.txt` reads a file of recipients (one per line,
`#` comments allowed). The key file that `keygen --type age` writes is in the standard age format,
so `age -i key.txt` works on it too.

## Why this is Python-only

age uses **ChaCha20-Poly1305**. The browser's Web Crypto API does not expose ChaCha20-Poly1305 — only
AES-GCM — so the HTML viewer and the GUI cannot open age files. age support lives in the CLI, and the
Python module is `lockhtml/age.py`.

## How this was verified

Reading the specification is not the same as implementing it correctly, so the implementation was
checked against the **reference implementation**, not against my own reading of the spec:

1. **The official test vector.** `testdata/example.age` and `testdata/example_keys.txt` from
   [FiloSottile/age](https://github.com/FiloSottile/age) are embedded in `tests/test_age.py`, so CI
   decrypts a real age file (produced by the reference tool) without needing network access.
2. **Bidirectional interop** against the `age` v1.2.1 binary, for: empty input, a single byte,
   64 KiB−1, **exactly 64 KiB**, exactly 128 KiB, 64 KiB+1, multi-chunk, and binary data with NUL
   bytes — both directions (reference→us and us→reference), plus multi-recipient files.

That exercise caught a real bug. A payload whose length is an **exact multiple of the 64 KiB chunk
size** was decrypted incorrectly: the final chunk is full-sized, so a naive reader treats it as a
non-final chunk and the tag check fails. The reference binary is what surfaced it — the spec sentence
that matters ("the final chunk MAY be shorter than 64 KiB") does not make the exact-multiple case
obvious. It is now covered by `test_age_round_trip_sizes[65536]` and `[131072]`.

## Security notes

- **Not audited.** This is a from-scratch implementation of a published format. It interoperates with
  the reference implementation on the cases above, but it has not had an independent security review.
  For anything that matters, prefer the reference `age` tool.
- The implementation refuses a **low-order** X25519 share (an all-zero shared secret) rather than
  proceeding, as the spec requires.
- It checks the body length of an `X25519` stanza is exactly 32 bytes before attempting to decrypt
  it, to blunt partitioning-oracle attacks.
- The **header MAC is always verified** before the payload is decrypted, so a modified header is
  rejected even if the payload would otherwise decrypt.
