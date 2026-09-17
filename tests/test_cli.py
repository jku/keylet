# SPDX-License-Identifier: MIT
# Copyright (c) 2026 keylet authors

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

from keylet.bin.cli import _app_signer, cmd_sign


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


def test_cmd_sign_streams_file(tmp_path: Path) -> None:
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"hello streaming")

    args = argparse.Namespace(
        file=str(test_file),
        pubkey=None,
        type="ml-dsa",
        digest=None,
    )

    mock_signer = MagicMock()
    mock_signer.sign.return_value = b"signed_signature_bytes"

    with patch("keylet.bin.cli._app_signer") as mock_app_signer_ctx:
        mock_app_signer_ctx.return_value.__enter__.return_value = mock_signer
        cmd_sign(args)

    mock_signer.sign.assert_called_once()
    called_file_arg = mock_signer.sign.call_args[0][0]
    assert hasattr(called_file_arg, "read")

    sig_file = tmp_path / "test.txt.signature"
    assert sig_file.exists()
    assert sig_file.read_bytes() == b"signed_signature_bytes"
