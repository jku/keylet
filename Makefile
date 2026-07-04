.PHONY: all lint test

all: lint test

lint:
	uv run ruff format --diff .
	uv run ruff check .
	uv run mypy .
	uv run zizmor --quiet .

fix:
	uv run ruff format .
	uv run ruff check --fix .
	uv run zizmor --quiet --fix .

test:
	uv run pytest -v

test-device:
	uv run pytest -v --device
