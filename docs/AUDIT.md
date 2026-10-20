# Security self-audit — v1.1.0

> **Scope and honesty note.** This is a *self*-review carried out by the maintainer during the v1.1
> development cycle. It is **not** an independent third-party audit, and no external cryptographer
> has reviewed it. Treat it as a record of what was checked and what is known to be weak, not as a
> certification.

## What was reviewed

- `lockhtml/core.py` — key derivation, encryption, signing, decoy handling, locked-file assembly.
- `lockhtml/templates/viewer.src.html` — the in-browser unlock path (including the generated
  `viewer.html` and `viewer-argon2.html`).
- `lockhtml/gui/app.html` — the locking path in the browser.
- The build and minification pipeline (`tools/build.py`, `tools/minify.mjs`).

## Method

1. **Code review** of every cryptographic path against the format spec (`docs/FORMAT.md`).
2. **Cross-implementation testing.** Files locked by the Python CLI were opened in a real headless
   Chrome; files locked by the browser code were decrypted by the Python CLI. Both directions were
   run for Argon2id, PBKDF2 and keyfile modes.
3. **Negative testing.** Wrong PIN, missing keyfile, wrong keyfile, and tampered ciphertext were each
   confirmed to fail.
4. **Plaintext-leak testing.** Assertions that the secret string never appears in a locked file.
5. **Property checks.** Randomness of salt/IV, Unicode round-trips, and legacy v1 readability.

## Streaming container review (v1.2)

The chunked container was reviewed specifically for the failure modes that naive chunking
introduces:

| Risk | Mitigation | Test |
| --- | --- | --- |
| Nonce reuse across chunks | Nonce = `base_iv \|\| uint32_be(index)`; a fresh `base_iv` per file | round-trip, many-chunk |
| Chunk reordering / swapping | Chunk index bound as AAD | tampered-chunk test |
| Truncation | MAC covers `chunkCount` and every tag | truncation test |
| Extra data appended | Trailing bytes rejected | trailing-data test |
| Metadata tampering (limits, size, count) | Metadata is inside the MAC input | metadata-tamper test |
| Wrong container | 5-byte magic checked first | browser e2e |

All of these are covered by automated tests, and the browser path is exercised in CI against files
produced by the Python core.

**Known limitation.** Assembling the decrypted output in the browser still costs O(file), because the
viewer collects the chunks into a `Blob`. Reading and decryption are O(chunk size). Constant-memory
output needs the File System Access API and is on the roadmap.

## Recipient mode review (v1.3)

X25519 hybrid encryption was reviewed against the usual ECIES pitfalls:

| Risk | Mitigation | Test |
| --- | --- | --- |
| Ephemeral key reuse | A fresh keypair per file | `test_recipient_ephemeral_is_random` |
| Low-entropy key fed to AES directly | Shared secret passes through HKDF-SHA256 | round-trip tests |
| Wrong recipient key accepted | GCM authentication fails | `test_recipient_wrong_key_fails` |
| Optional PIN silently ignored | `pin` flag in the payload gates whether it is mixed in | `test_recipient_with_pin` |
| Ephemeral key swapped by an attacker | Covered by the streaming MAC in stream mode | `test_recipient_stream_metadata_tamper` |
| Decoy PIN in recipient mode | Rejected outright rather than ignored | `test_recipient_decoy_not_allowed` |

**Known limitation.** A leaked private key cannot be revoked; anyone holding it can open every file
locked to that key. Key rotation is the only remedy, and it is the user's responsibility.

## Shares mode review (v1.4)

Shamir secret sharing was reviewed against the standard failure modes:

| Risk | Mitigation | Test |
| --- | --- | --- |
| Wrong field arithmetic | GF(256) checked against the FIPS-197 vector and all 255 inverses | `test_gf_arithmetic` |
| Python and JS disagree | Both implement the same polynomial; cross-checked by browser e2e and GUI→Python | `e2e_browser.mjs`, `e2e_gui_verify.py` |
| Fewer than k shares leak the secret | Any 2 of a 3-of-5 set must not reconstruct | `test_shamir_insufficient_shares` |
| Duplicate / invalid indices | Rejected outright | `test_shamir_rejects_bad_shares` |
| A wrong extra share corrupting a valid set | Only the first k shares are used | `test_shares_mode_round_trip` |
| Tampering with n or k | Covered by the streaming MAC | `test_shares_stream_metadata_tamper` |
| Shares leaking into the locked file | Shares are returned separately and never embedded | `test_shares_mode_round_trip` asserts plaintext absence |

**Known limitation.** Any *k* holders can reconstruct the seed, and a reconstructed seed cannot be
revoked — the file must be re-locked with a fresh split if shares are exposed.

## v2.0 review (hidden volumes, auto-KDF, streaming decoy)

| Risk | Mitigation | Test |
| --- | --- | --- |
| A hidden slot leaks into the cover view | Slots are tried only after the main payload fails | `test_hidden_volume` asserts the hidden text is absent from the file |
| Wrong PIN opening the wrong slot | Each slot has its own salt/IV and GCM tag | `test_hidden_volume_multiple_slots` |
| A decoy blob being swapped in a stream | Its ciphertext is covered by the streaming MAC | `test_streaming_decoy` |
| Auto-KDF picking an unusable cost | `t` is clamped to 1..64 and the params are stored per file | `test_calibrate_argon2` |
| Hidden slots in recipient mode (no PIN to key them) | Rejected outright | `test_hidden_rejected_in_recipient_mode` |

**Known limitation.** Hidden slots are *visible* in the file's JSON; they are unreadable without their
PIN but their presence is not concealed.

## Findings

### Fixed during this cycle

| # | Finding | Severity | Resolution |
| --- | --- | --- | --- |
| 1 | The keyfile was accepted as a parameter but **not actually mixed into the Argon2 key**, so a keyfile-protected file could be opened with the PIN alone. | **High** | Keyfile is now mixed via `HMAC-SHA256(derived, keyfile)` in both Python and JS, with tests and a browser end-to-end check. |
| 2 | `unlock()` returned text, silently corrupting binary payloads. | Medium | Returns raw bytes; binary round-trip is tested. |
| 3 | A minifier configuration produced assets that failed to parse. | Low | Config corrected; CI now rebuilds and diffs the generated assets so a broken build cannot be committed. |
| 4 | `unlock` with `-o` stopped writing the plaintext for the embedded container after the streaming branch was added. | Medium | Caught by the test suite; fixed and covered by `test_cli_lock_and_unlock`. |
| 5 | `build_locked_html` still required a positional `pin`, so recipient mode could not be used through it. | Low | Made optional; covered by the recipient CLI test. |
| 6 | The GUI's shares helper referenced a non-existent `payload_pin()` function. | Low | Caught while wiring the UI; replaced with the direct argument. |
| 7 | The browser e2e suite died part-way through a long run (detached frame, then the whole browser). | Medium | Not a product bug: a memory-tight container. The harness now recycles the page every few checks and relaunches Chrome if it dies. |
| 8 | `gui.sh` `exec`'d `lockhtml.sh`, which has no executable bit, so it failed with `Permission denied` — the launcher simply did not work. | High | Runs the launcher through `sh`; the launcher test now executes `gui.sh` instead of only syntax-checking it. |
| 9 | The GUI's Lock button stayed disabled when using a recipient key or a share split, because only the PIN field had an input listener. | High | Listeners added on both fields; the button re-evaluates as you type. |
| 10 | The GUI silently dropped a hidden PIN when combined with recipient or split mode, so a user could believe a hidden volume existed when it did not. | High | Now an explicit error, matching the CLI's behaviour. |
| 11 | `lockhtml.bat` used `%PY%` unquoted, breaking on Python paths containing spaces. | Medium | Quoted at every use site. |
| 12 | `unlock()`/`decrypt()` on a streaming payload raised a bare `KeyError` instead of explaining that the sidecar is needed. | Low | Explicit `ValueError`; covered by `test_unlock_rejects_stream_payload`. |
| 13 | `make minify` minified without rebuilding first. Minify is not idempotent, so this could leave an asset that CI rejects. | Medium | `make minify` is now an alias for `make build`; `build + minify` is verified deterministic. |

### Reviewed and judged acceptable

- **Random 96-bit IVs.** Each key encrypts exactly one message, so the AES-GCM IV-reuse bound is not
  approached.
- **`id = sha256(ct)[0:8]`.** Reveals nothing about the plaintext; used only as a local counter key.
- **Sandboxed iframe without `allow-same-origin`.** A decrypted document cannot read the viewer's
  storage.
- **Signature checked before decryption.** A tampered file is refused, not merely flagged.
- **No network access at runtime.** The Argon2 WASM is inlined; the viewer makes no requests.

### Known limitations (by design, documented)

- **View limits, expiry and one-time view are client-side.** They are stored in IndexedDB (with a
  `localStorage` fallback) and can be defeated by a determined recipient. This is a deterrent, not a
  guarantee.
- **Watermarking is visible-only.** It aids leak tracing; it does not prevent screenshots.
- **No CSP is set on the viewer.** The viewer requires inline scripts and `srcdoc`, so a strict CSP
  would need care; this is a hardening opportunity rather than a vulnerability in the current model.
- **Ed25519 verification needs a modern browser.** Current Chrome, Firefox and Safari support it;
  older browsers warn and proceed. There is no WASM fallback yet.
- **PIN strength is the user's responsibility.** Argon2id raises the cost of brute force but does not
  rescue a four-digit PIN. The GUI includes a generator and a strength meter.

## Recommendations for users

- Use a **passphrase**, not a short numeric PIN, and send it over a different channel than the file.
- Use a **keyfile** for anything sensitive, and deliver it separately again.
- **Sign** files you send so the recipient can detect tampering.
- Treat one-time view and expiry as conveniences, not protections.

## Recommendations for future work

- Add a Content-Security-Policy to the viewer (needs care with inline scripts and `srcdoc`).
- Add a WASM fallback for Ed25519 verification on older browsers.
- Commission an **independent** review before describing the project as "audited".
