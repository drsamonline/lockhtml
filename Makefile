.PHONY: help install test build minify lock-example dist clean

help:
	@echo "LockHTML - available targets:"
	@echo "  make install       Install the package in editable mode with dev tools"
	@echo "  make test          Run the test suite"
	@echo "  make build         Regenerate + minify the GUI and viewer templates"
	@echo "  make minify        Minify generated assets only"
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

minify:
	node tools/minify.mjs

lock-example:
	lockhtml lock examples/sample.html --pin 4821 --kdf pbkdf2 -o examples/sample.locked.html

dist:
	python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
