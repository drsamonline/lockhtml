# Contributing to LockHTML

Thanks for your interest! Contributions of all kinds are welcome — bug reports,
feature ideas, documentation fixes and code.

## Getting set up

```bash
git clone https://github.com/drsamonline/lockhtml
cd lockhtml
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
npm install        # build tooling: minifier + Argon2 WASM
```

## Running the tests

```bash
make test        # or: python -m pytest
```

### End-to-end browser tests

These open files locked by the CLI in a real headless Chrome and check every behaviour, for both
containers. They need a Chrome/Chromium binary.

```bash
make e2e         # fixtures + browser test (embedded + streaming)
make e2e-gui     # GUI code path -> verified by the Python core
```

Set `CHROME=/path/to/chrome` if puppeteer-core cannot find one.

## Regenerating the generated assets

Three files are generated and must not be hand-edited:

- `lockhtml/templates/viewer.html` and `lockhtml/templates/viewer-argon2.html` —
  built from `lockhtml/templates/viewer.src.html`, with the Argon2id WASM inlined
  into the second.
- `lockhtml/gui/index.html` — built from `lockhtml/gui/app.html`, with both viewer
  templates inlined.

After editing `viewer.src.html` or `app.html`, rebuild and minify:

```bash
npm install
make build       # python tools/build.py && node tools/minify.mjs
```

CI verifies the committed assets match the sources, so always run `make build`
before committing.

## Project conventions

- The CLI (Python) and GUI (JavaScript) must stay **format-compatible**. Any change to
  the payload schema must be made in both, and covered by a test.
- Keep the payload format documented in `lockhtml/core.py`.
- Add a test for every behavioural change.
- Match the existing code style; keep dependencies minimal.

## Submitting changes

1. Fork the repo and create a branch: `git checkout -b feature/my-change`.
2. Make your change and add tests.
3. Run `make test` and `make gui`.
4. Open a pull request describing what changed and why.

By contributing you agree that your contributions are licensed under the
[PolyForm Noncommercial License 1.0.0](LICENSE).
