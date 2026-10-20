.PHONY: help install test gui lock-example build clean

help:
	@echo "LockHTML - available targets:"
	@echo "  make install       Install the package in editable mode with dev tools"
	@echo "  make test          Run the test suite"
	@echo "  make gui           Regenerate lockhtml/gui/index.html from app.html"
	@echo "  make lock-example  Rebuild examples/sample.locked.html"
	@echo "  make build         Build wheel and sdist"
	@echo "  make clean         Remove build artefacts"

install:
	pip install -e ".[dev]"

test:
	python -m pytest

gui:
	python tools/build_gui.py

lock-example:
	lockhtml lock examples/sample.html --pin 4821 -o examples/sample.locked.html

build:
	python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
