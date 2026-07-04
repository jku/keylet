# SPDX-License-Identifier: MIT
# Copyright (c) 2026 keylet authors

import os
from collections.abc import Generator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PublicKey

from keylet.tkey import (
    APP_MAXSIZE,
    TKey,
    TKeyAppError,
    TKeyDeviceBusyError,
    TKeyNotFoundError,
)
from keylet.tkey_sign import SignApp, SignCmd, TKeySign

# Path to the no-touch test binary. This binary was built from
# https://github.com/tillitis/tkey-pq-device-signer with
# * app_name1 changed to "pqnt" to make it different from real signer
# * built with "TKEY_SIGNER_APP_NO_TOUCH=yesplease"
TEST_BIN_PATH = Path(__file__).parent / "resources" / "app_no_touch.bin"


def _test_signer() -> TKeySign:
    if not TEST_BIN_PATH.exists():
        pytest.fail(f"Test binary not found at {TEST_BIN_PATH}")

    binary = TEST_BIN_PATH.read_bytes()
    test_app = SignApp(binary, 3, ("tk1", "pqnt"), 2420, 1312)
    passphrase = os.environ.get("TKEY_TEST_PASSPHRASE")

    try:
        return TKeySign(test_app, secret=passphrase)
    except TKeyNotFoundError:
        pytest.fail("TKey device not found. Please ensure it is plugged in.")
    except TKeyAppError as e:
        try:
            with TKey(None) as tkey:
                rx = tkey.send(SignCmd.GET_NAMEVERSION)
                name = (
                    rx[2:6].decode("ascii").rstrip(),
                    rx[6:10].decode("ascii").rstrip(),
                )
                version = int.from_bytes(rx[10:14], byteorder="little")

            pytest.fail(
                f"TKey is running an unexpected device application {name} v{version}. "
                "Please unplug and replug the TKey to reset it to firmware mode, "
                "then run the tests again. "
            )
        except Exception:
            pytest.fail(f"Failed to initialize TKey with test device application: {e})")


@pytest.fixture(scope="module")
def device_signer() -> Generator[TKeySign, None, None]:
    signer = _test_signer()
    yield signer
    signer.disconnect()


@pytest.mark.device
def test_device_connections() -> None:
    """Device can be connected to several times, but not concurrently"""
    with _test_signer():
        pass

    with _test_signer():
        pass

    with _test_signer():
        with pytest.raises(TKeyDeviceBusyError, match=" is busy"):
            _test_signer()
        pass


@pytest.mark.device
def test_device_not_found() -> None:
    test_app = SignApp(b"", 3, ("tk1", "pqnt"), 2420, 1312)
    with pytest.raises(TKeyNotFoundError):
        TKeySign(test_app, device="notadevice")


@pytest.mark.device
def test_device_application_load() -> None:
    # make sure app is loaded first
    with _test_signer():
        pass

    fake_app = SignApp(b"0" * (APP_MAXSIZE + 1), 3, ("tk1", "pqnt"), 2420, 1312)
    with pytest.raises(TKeyAppError, match="too large"):
        TKeySign(fake_app)

    fake_app = SignApp(b"", 2, ("tk1", "pqnt"), 2420, 1312)
    with pytest.raises(TKeyAppError, match="unknown application"):
        TKeySign(fake_app)

    fake_app = SignApp(b"", 3, ("tk1", "fake"), 2420, 1312)
    with pytest.raises(TKeyAppError, match="unknown application"):
        TKeySign(fake_app)


@pytest.mark.device
def test_device_pubkey_retrieval_and_validation(device_signer: TKeySign) -> None:
    """Retrieve the public key from the device and verify it is a valid
    ML-DSA-44 key.
    """
    pubkey_bytes = device_signer.get_pubkey()
    assert len(pubkey_bytes) == device_signer.key_size

    # Ensure it can be parsed successfully by the cryptography library
    pubkey = MLDSA44PublicKey.from_public_bytes(pubkey_bytes)
    assert pubkey is not None


@pytest.mark.device
def test_device_sign_and_verify(device_signer: TKeySign) -> None:
    """Sign a message on the physical device and verify the signature on the host."""
    message = b"Hello from TKey on-device test suite!"

    pubkey_bytes = device_signer.get_pubkey()
    pubkey = MLDSA44PublicKey.from_public_bytes(pubkey_bytes)

    # Sign the message (blocks waiting for touch, but our test binary has
    # no-touch enabled)
    signature = device_signer.sign(message, pub_key=pubkey_bytes)
    assert len(signature) == device_signer.sig_size

    # Verify the signature on the host using the public key
    pubkey.verify(signature, message)
