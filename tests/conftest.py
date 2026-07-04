# SPDX-License-Identifier: MIT
# Copyright (c) 2026 keylet authors

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--device",
        action="store_true",
        default=False,
        help="run on-device tests against a physical TKey",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--device"):
        # --device option is provided, do not skip
        return

    skip_device = pytest.mark.skip(reason="need --device option to run")
    for item in items:
        if "device" in item.keywords:
            item.add_marker(skip_device)
