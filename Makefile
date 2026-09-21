.PHONY: all lint test release

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

# "make release" will only make the current dev release stable: If you want
# a version bump, use "uv version --bump=[major|minor]" first
release:
	@set -e; \
	VER=$$(uv version --short); \
	case "$$VER" in *dev*) \
		VER=$$(uv version --dry-run --short --bump=stable) ;; \
	esac; \
	if ! grep -E -q "^## v$$VER([[:space:]]|$$)" CHANGELOG.md; then \
		sed -i '/^## Unreleased/a \\n## v'"$$VER" CHANGELOG.md; \
	fi; \
	case "$$(uv version --short)" in *dev*) \
		uv version --quiet --bump=stable ;; \
	esac; \
	git --no-pager diff; \
	printf "\nPress Enter to create release commit (or Ctrl-C to abort)... "; \
	read -r _ < /dev/tty; \
	if ! git diff --quiet; then \
		git commit -a -m "Version bump for $$VER release"; \
	fi; \
	git tag -m "$$VER" "v$$VER"; \
	VER=$$(uv version --dry-run --short --bump=dev --bump=patch); \
	uv version --quiet --bump=dev --bump=patch; \
	git commit -a -m "dev version bump to $$VER"
