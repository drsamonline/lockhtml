# Design notes: why there are two containers

This document explains the size limits of LockHTML, why they exist, and how the
streaming container removes them. It is written for anyone who wants to understand the
trade-offs rather than just the commands.

## The short version

- **Embedded container** (default): the whole file is encrypted at once and its ciphertext is
  embedded in the HTML as base64. Convenient — one file — but memory use is roughly **3–4×** the
  file size, so it is comfortable up to ~50 MB and breaks somewhere around 250–300 MB.
- **Streaming container** (`--stream`): the ciphertext goes into a sidecar `.bin`, encrypted in
  fixed-size chunks. Reading and decryption cost **~O(chunk size)**, so multi-gigabyte files work.
  The cost is that the recipient gets **two files** instead of one.

Both are **100% offline**. "Streaming" here refers to *memory*, not the network — see
[Streaming is not about the internet](#streaming-is-not-about-the-internet).

## Why the embedded container has a ceiling

The embedded path, in both the CLI and the browser, is:

1. Read the entire file into memory.
2. Encrypt it in a single AES-GCM call.
3. Base64-encode the ciphertext so it can sit inside an HTML `<script>` tag.

Step 3 is the expensive one. Base64 inflates data by **4/3 (≈1.33×)**, and it is held as a
JavaScript *string*, which the browser also caps. At peak, several copies exist at once:

| Copy | Size (for an *N*-byte file) |
| --- | --- |
| Source bytes | *N* |
| Ciphertext | *N* + 16 |
| Base64 string | ≈ 1.33·*N* |
| Final HTML string | ≈ 1.33·*N* |
| **Peak total** | **≈ 3.7·*N*** |

The hard limit is the maximum length of a single JavaScript string: roughly **512 MB** in V8
(Chrome, Edge, Node). Base64 of a ~400 MB file already exceeds it. Mobile browsers give up far
earlier. The Python CLI has the same shape — it also holds the file, the ciphertext and the
base64 copy — so a 1 GB file wants ~3.7 GB of RAM.

In practice:

| Source file | Peak memory (approx) | Embedded container today |
| --- | --- | --- |
| up to ~10 MB | ~40 MB | Instant, on any device |
| ~10–50 MB | ~200 MB | Fine on desktop, slow on phones |
| ~50–200 MB | ~800 MB | Desktop only, noticeably slow |
| **> ~250–300 MB** | **> 1 GB** | **Likely fails** |

Two further consequences worth knowing:

- The locked file is always **≈1.34× the original** plus ~60 KB of viewer, because of base64.
- The browser must parse that entire string when the file is opened, so opening a large embedded
  file is slow even if it fits in memory.

## How the streaming container works

`--stream` splits the plaintext into fixed-size chunks (default **1 MiB**, tunable with
`--chunk-size`) and never holds more than a chunk or two:

- Each chunk is encrypted **separately** with AES-GCM.
- Each chunk gets its **own nonce**, derived deterministically as
  `base_iv (8 random bytes) || uint32_be(chunk index)`. This guarantees a nonce is never reused
  with the same key — reuse would be catastrophic for GCM.
- The **chunk index is passed as Additional Authenticated Data**, so chunks cannot be reordered,
  duplicated, dropped or truncated. This is the standard "STREAM" construction; without it,
  naive chunking would be *less* safe than encrypting in one piece.
- Whole-file integrity is bound by a MAC over the metadata **and every chunk tag**:

  ```
  mac_input = meta_string || tag_0 || tag_1 || ... || tag_{n-1}
  metamac   = HMAC-SHA256(key, mac_input)
  signature = Ed25519(mac_input)      # optional, when signed
  ```

  Because `meta_string` covers the chunk count, chunk size, KDF parameters, salt, base IV, kind,
  filename and the view/expiry limits, tampering with any of them is detected.

The sidecar file is simply:

```
"LKHS1" || chunk_0 || chunk_1 || ... || chunk_{n-1}
```

Each chunk is `ciphertext || 16-byte GCM tag`. Because there is no base64, the sidecar is only
about **16 bytes per chunk** larger than the original file.

The full byte-level specification is in [FORMAT.md](FORMAT.md#streaming-container).

### Reading it back with low memory

In the browser the sidecar is a `File` object, and the viewer reads it with
`file.slice(offset, offset + size)` — so chunks are pulled in lazily, decrypted one at a time, and
released. Reading and decryption are therefore **O(chunk size)**.

One honest caveat: **assembling the output still costs O(file)**. The viewer collects the decrypted
chunks into a `Blob` to hand to the browser. Truly constant-memory *output* needs the File System
Access API (`showSaveFilePicker`), which is Chromium-only today; that is a future improvement
listed in the roadmap. The CLI has no such limit — it streams straight to disk.

## Streaming is not about the internet

This trips people up, so it is worth stating plainly: **LockHTML never uses the network at any
size.** There is no server, no upload and no fetch. Everything — encryption, decryption, the
Argon2id WASM — runs locally.

"Streaming" is about **memory**, not connectivity. The streaming container is exactly as offline
as the embedded one; it simply processes the file in pieces instead of all at once. You can lock a
20 GB file on a plane with the Wi-Fi off.

## Choosing a container

| | Embedded (default) | Streaming (`--stream`) |
| --- | --- | --- |
| Files the recipient gets | 1 | 2 (`.html` + `.bin`) |
| Practical size ceiling | ~250–300 MB | Limited by disk, not memory |
| Memory (encrypt/decrypt) | ~3.7× file size | ~O(chunk size) |
| Output size overhead | ≈33% (base64) | ≈16 bytes per chunk |
| Decoy PIN | ✅ | ❌ (not yet) |
| Everything else (KDF, keyfile, signing, limits, watermark) | ✅ | ✅ |

Rule of thumb: **use the default for documents; use `--stream` for video, disk images, archives
or anything over ~100 MB.**

```bash
lockhtml lock holiday.mp4 --pin 4821 --stream
# -> holiday.locked.html  +  holiday.locked.bin

lockhtml unlock holiday.locked.html --pin 4821 --data holiday.locked.bin -o holiday.mp4
```

In the GUI, tick **“Streaming bundle (large files)”**; it downloads both files. The recipient
drops the `.html` in as usual and adds the `.bin` when prompted.
