.PHONY: help install install-dev test test-rust lint-rust build-rust lint typecheck format demo demo-conflict clean

help:
	@echo "KedgeFlow Development Commands:"
	@echo "  make build-rust     Build the v0.9 Rust reference gateway"
	@echo "  make test-rust      Run required real-etcd and official MCP SDK tests"
	@echo "  make lint-rust      Rust format and clippy checks"
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

build-rust:
	cargo build --locked --bin kf-proxy

test-rust:
	npm ci --prefix tests/sdk
	KF_REQUIRE_SDK=1 scripts/start-etcd.sh -- cargo test --locked --workspace --all-targets -- --nocapture

lint-rust:
	cargo fmt --all -- --check
	cargo clippy --locked --workspace --all-targets -- -D warnings

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
