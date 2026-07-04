.PHONY: all lint test

all: lint test

lint:
	uv run ruff format .
	uv run ruff check .
	uv run mypy .

test:
	uv run pytest -v

test-device:
	uv run pytest -v --device
