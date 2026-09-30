.PHONY: help install install-dev test lint typecheck format demo demo-conflict clean

help:
	@echo "KedgeFlow Development Commands:"
	@echo "  make install        Install package in editable mode"
	@echo "  make install-dev    Install package with dev dependencies"
	@echo "  make test           Run test suite"
	@echo "  make lint           Check code formatting and style"
	@echo "  make typecheck      Run static type checking"
	@echo "  make format         Auto-format code"
	@echo "  make demo           Run hello_kedgeflow example"
	@echo "  make demo-conflict  Run conflicting_agents example"
	@echo "  make clean          Remove build and cache artifacts"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check .

typecheck:
	mypy src

format:
	ruff format .
	ruff check --fix .

demo:
	python examples/hello_kedgeflow.py

demo-conflict:
	python examples/conflicting_agents.py

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
