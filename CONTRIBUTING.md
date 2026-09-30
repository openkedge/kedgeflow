# Contributing to KedgeFlow

Thank you for your interest in contributing to KedgeFlow! KedgeFlow is an open protocol and reference implementation for separating the control plane from the data plane in AI agent systems, developed under the OpenKedge umbrella.

## Guiding Principles

1. **Cognition Proposes, Control Authorizes, Execution Enforces, Execution Proves**: All contributions must respect this architectural boundary.
2. **Framework Neutrality**: Do not tie core protocol semantics to a specific agent framework or LLM provider.
3. **Transport Independence**: Protocol objects and lifecycle states must not assume HTTP, gRPC, or in-memory execution.
4. **Simplicity Over Over-Engineering**: Avoid unnecessary infrastructure dependencies.

## Development Setup

KedgeFlow requires Python 3.11+.

```bash
# Clone the repository
git clone https://github.com/openkedge/kedgeflow.git
cd kedgeflow

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development dependencies
make install-dev
```

## Running Tests and Quality Checks

Before submitting a pull request, ensure all tests, lint checks, and type checks pass:

```bash
# Run unit and integration tests
make test

# Run linter
make lint

# Run type checker
make typecheck

# Format code
make format
```

## Submitting Pull Requests

1. Fork the repository and create your branch from `main`.
2. Ensure new features or bug fixes are accompanied by tests.
3. Keep PRs focused on a single change or feature.
4. Follow conventional commit messages.
5. Ensure CI passes cleanly.

## Community and Discussion

KedgeFlow is part of OpenKedge. For architectural discussions and ACP (Agentic Control Plane) research, please open a GitHub Discussion or Issue.
