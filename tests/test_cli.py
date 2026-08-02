# SPDX-License-Identifier: MIT
# Copyright (c) 2026 keylet authors

import argparse
from unittest.mock import MagicMock, patch

from keylet.bin.cli import _app_signer


def test_app_signer_with_empty_passphrase() -> None:
    args = argparse.Namespace(type="ml-dsa", digest=None)
    with (
        patch("keylet.bin.cli.SignApp.load_mldsa") as mock_load,
        patch("keylet.bin.cli.TKeySign") as mock_tkeysign,
        patch("keylet.bin.cli.getpass.getpass", return_value="") as mock_getpass,
    ):
        mock_app = MagicMock()
        mock_app.digest = "123456789"
        mock_load.return_value = mock_app
        mock_signer_ctx = MagicMock()
        mock_tkeysign.return_value = mock_signer_ctx

        with _app_signer(args) as signer:
            assert signer == mock_signer_ctx.__enter__.return_value

        mock_getpass.assert_called_once_with(
            "Enter passphrase (press Enter for none): "
        )
        mock_tkeysign.assert_called_once_with(mock_app, secret=None)


def test_app_signer_with_passphrase() -> None:
    args = argparse.Namespace(type="ml-dsa", digest=None)
    with (
        patch("keylet.bin.cli.SignApp.load_mldsa") as mock_load,
        patch("keylet.bin.cli.TKeySign") as mock_tkeysign,
        patch(
            "keylet.bin.cli.getpass.getpass", return_value="mysecret"
        ) as mock_getpass,
    ):
        mock_app = MagicMock()
        mock_app.digest = "123456789"
        mock_load.return_value = mock_app
        mock_signer_ctx = MagicMock()
        mock_tkeysign.return_value = mock_signer_ctx

        with _app_signer(args) as signer:
            assert signer == mock_signer_ctx.__enter__.return_value

        mock_getpass.assert_called_once_with(
            "Enter passphrase (press Enter for none): "
        )
        mock_tkeysign.assert_called_once_with(mock_app, secret="mysecret")
