.PHONY: help install test build minify e2e e2e-gui lock-example dist clean

help:
	@echo "LockHTML - available targets:"
	@echo "  make install       Install the package in editable mode with dev tools"
	@echo "  make test          Run the test suite"
	@echo "  make build         Regenerate + minify the GUI and viewer templates"
	@echo "  make minify        Alias for build (minify must follow a fresh build)"
	@echo "  make e2e           End-to-end browser test (needs Chrome)"
	@echo "  make e2e-gui       GUI code path -> Python verification"
	@echo "  make lock-example  Rebuild examples/sample.locked.html"
	@echo "  make dist          Build wheel and sdist"
	@echo "  make clean         Remove build artefacts"

install:
	pip install -e ".[dev]"
	npm install

test:
	python -m pytest

build:
	python tools/build.py
	node tools/minify.mjs

# NOTE: always regenerate from source before minifying. Minifying an
# already-minified index.html is not idempotent, so a bare `minify` would leave
# an asset that CI (which runs build + minify) rejects.
minify: build

e2e:
	python tools/e2e_fixtures.py /tmp/lockhtml-e2e
	node tools/e2e_browser.mjs /tmp/lockhtml-e2e

e2e-gui:
	node tools/e2e_gui.mjs /tmp/lockhtml-gui
	python tools/e2e_gui_verify.py /tmp/lockhtml-gui

lock-example:
	lockhtml lock examples/sample.html --pin 4821 --kdf pbkdf2 -o examples/sample.locked.html

dist:
	python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
