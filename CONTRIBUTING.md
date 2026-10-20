# Contributing to LockHTML

Thanks for your interest! Contributions of all kinds are welcome — bug reports,
feature ideas, documentation fixes and code.

## Getting set up

```bash
git clone https://github.com/drsamonline/lockhtml
cd lockhtml
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running the tests

```bash
make test        # or: python -m pytest
```

## Regenerating the GUI

The GUI is generated — `lockhtml/gui/index.html` is built from
`lockhtml/gui/app.html` plus the viewer template `lockhtml/templates/viewer.html`.
If you edit either, rebuild:

```bash
make gui         # or: python tools/build_gui.py
```

Never hand-edit `lockhtml/gui/index.html`; edit `app.html` and rebuild.

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
[MIT License](LICENSE).
