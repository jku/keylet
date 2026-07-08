# SPDX-License-Identifier: MIT
# Copyright (c) 2026 keylet authors

"""Keylet TKey signer implementation"""

from __future__ import annotations

import hashlib
import importlib.resources
import logging
from dataclasses import dataclass

from keylet.tkey import Cmd, LenIdx, Rsp, TKey, TKeyError, TKeyUnexpectedAppError

logger = logging.getLogger(__name__)

MU_SIZE = (64).to_bytes(4, byteorder="little")
MAX_PAYLOAD_SIZE = 4096

# Static registry of signer binaries (filename, version)
# First binary in each list is the default binary.
_EMBEDDED_MLDSA_BINS: list[tuple[str, int]] = [
    ("pqsigner_v3.bin", 3),
]

_EMBEDDED_ED25519_BINS: list[tuple[str, int]] = [
    ("ed25519signer_v3.bin", 3),
]


@dataclass
class SignApp:
    """Configuration and binary data for the TKey device signer application.

    Attributes:
        binary: The raw bytes of the device application binary.
        version: The version number of the device application.
        name: Device application name tuple.
        sig_size: The size of the generated signature in bytes.
        key_size: The size of the public key in bytes.
    """

    binary: bytes
    version: int
    name: tuple[str, str]
    sig_size: int
    key_size: int

    @property
    def digest(self) -> str:
        """Return the BLAKE2s-256 hex digest of the application binary."""
        return hashlib.blake2s(self.binary, digest_size=32).hexdigest()

    @classmethod
    def _find_binary(
        cls, version: int | None, digest: str | None, bins: list[tuple[str, int]]
    ) -> tuple[bytes, int]:
        resources_dir = importlib.resources.files("keylet.resources")
        matches = []

        # Scan registered binaries
        for filename, file_ver in bins:
            # Filter by version if requested
            if version is not None and file_ver != version:
                continue

            binary = resources_dir.joinpath(filename).read_bytes()
            file_digest = hashlib.blake2s(binary, digest_size=32).hexdigest()

            # Filter by digest if requested
            if digest is not None and not file_digest.startswith(digest.lower()):
                continue

            matches.append((binary, file_ver))

            if digest is None and version is None:
                # First binary is the default one
                break

        if not matches:
            raise ValueError(
                f"No device binary found matching: version={version}, digest={digest}"
            )

        if len(matches) > 1:
            raise ValueError(
                f"Multiple device binaries found matching: version={version}, "
                f"digest={digest}."
            )

        return matches[0]

    @classmethod
    def load_mldsa(
        cls, version: int | None = None, digest: str | None = None
    ) -> SignApp:
        """Load a ML-DSA signer application from package resources.

        If a digest (or prefix) is provided, it returns the binary matching the
        digest. If a version is provided, it filters by version. If neither is
        provided, current default binary is loaded.

        TKey key derivation depends on the application binary, so users who want a
        specific key must provide the binary digest.

        Args:
            version: The version of the signer application to load.
            digest: A BLAKE2s-256 hex digest (or prefix) of the target binary.

        Returns:
            An instance of SignApp configured with the loaded binary.

        Raises:
            ValueError: If no binary matches the criteria, or if the search
                is ambiguous (matches multiple binaries).
        """

        binary, version = cls._find_binary(version, digest, _EMBEDDED_MLDSA_BINS)
        return cls(binary, version, ("tk1", "pqsn"), 2420, 1312)

    @classmethod
    def load_ed25519(
        cls, version: int | None = None, digest: str | None = None
    ) -> SignApp:
        """Load a Ed25519 signer application from package resources.

        If a digest (or prefix) is provided, it returns the binary matching the
        digest. If a version is provided, it filters by version. If neither is
        provided, current default binary is loaded.

        TKey key derivation depends on the application binary, so users who want a
        specific key must provide the binary digest.

        Warning:
            When Ed25519 is used, there is a 4096B size limit to signing payloads.

        Args:
            version: The version of the signer application to load.
            digest: A BLAKE2s-256 hex digest (or prefix) of the target binary.

        Returns:
            An instance of SignApp configured with the loaded binary.

        Raises:
            ValueError: If no binary matches the criteria, or if the search
                is ambiguous (matches multiple binaries).
        """
        binary, version = cls._find_binary(version, digest, _EMBEDDED_ED25519_BINS)
        return cls(binary, version, ("tk1", "sign"), 64, 32)


class SignRsp:
    """Application responses"""

    GET_PUBKEY = Rsp(0x02, LenIdx.I128)
    SET_SIZE = Rsp(0x04, LenIdx.I4)
    LOAD_DATA = Rsp(0x06, LenIdx.I4)
    GET_SIG = Rsp(0x08, LenIdx.I128)
    GET_NAMEVERSION = Rsp(0x0A, LenIdx.I32)
    GET_FIRMWARE_HASH = Rsp(0x0C, LenIdx.I128)


class SignCmd:
    """Application commands"""

    GET_PUBKEY = Cmd(0x01, 3, LenIdx.I1, (SignRsp.GET_PUBKEY,))
    SET_SIZE = Cmd(0x03, 3, LenIdx.I32, (SignRsp.SET_SIZE,))
    LOAD_DATA = Cmd(0x05, 3, LenIdx.I128, (SignRsp.LOAD_DATA,))
    GET_SIG = Cmd(0x07, 3, LenIdx.I1, (SignRsp.GET_SIG,))
    GET_NAMEVERSION = Cmd(0x09, 3, LenIdx.I1, (SignRsp.GET_NAMEVERSION,))
    GET_FIRMWARE_HASH = Cmd(0x0B, 3, LenIdx.I32, (SignRsp.GET_FIRMWARE_HASH,))


class TKeySign(TKey):
    """Client for communicating with the TKey signer application.

    This class implements public key retrieval and signing as defined in the
    [tkey-pq-device-signer protocol](https://github.com/tillitis/tkey-pq-device-signer)
    but is also compatible with the
    [tkey-device-signer protocol](https://github.com/tillitis/tkey-device-signer).
    """

    def __init__(
        self,
        app: SignApp,
        device: str | None = None,
        secret: str | None = None,
    ) -> None:
        """Initialize the TKey signing client.

        If the TKey device is in firmware mode, this will automatically load the
        application binary. If the device is already running an application, it
        verifies that the running application matches the expected name and version.

        Args:
            app: The SignApp configuration containing the binary and metadata.
            device: Optional serial port path (e.g., `/dev/ttyACM0`). If None,
                the port is auto-detected.
            secret: Optional User Supplied Secret (passphrase) used as a seed
                for key derivation.

        Raises:
            TKeyNotFoundError: If the TKey device cannot be found.
            TKeyUnexpectedAppError: If loading the application fails or the device is
                running a mismatched application.
            TKeyError: For other connection or initialization failures.
        """
        super().__init__(device)
        self.key_size = app.key_size
        self.sig_size = app.sig_size
        self.name = app.name

        try:
            if not self.load_app(app.binary, secret):
                # TKey is not in firmware mode: Query application name and version
                rx = self.send(SignCmd.GET_NAMEVERSION)
                name = (
                    rx[2:6].decode("ascii").rstrip(),
                    rx[6:10].decode("ascii").rstrip(),
                )
                ver = int.from_bytes(rx[10:14], byteorder="little")
                if name == app.name and ver == app.version:
                    return  # Signer application is already loaded

                raise TKeyUnexpectedAppError(
                    f"TKey is running an unknown application {name, ver}, "
                    f"expected {app.name, app.version}"
                )
        except TKeyError:
            self.disconnect()
            raise

    def get_pubkey(self) -> bytes:
        """Retrieve the public key bytes from the TKey device.

        Returns:
            The raw public key bytes.

        Raises:
            TKeyIOError: If reading from the serial port fails.
            TKeyProtocolError: If there is a framing or protocol mismatch.
        """
        pubkey = bytearray(self.key_size)

        # Issue command, read first frame
        rx = self.send(SignCmd.GET_PUBKEY)
        offset = 0

        while offset < self.key_size:
            chunk_size = min(self.key_size - offset, 127)
            pubkey[offset : offset + chunk_size] = rx[2 : 2 + chunk_size]
            offset += chunk_size
            if offset < self.key_size:
                rx = self.recv_response(SignCmd.GET_PUBKEY)

        return bytes(pubkey)

    def sign(self, message: bytes, pub_key: bytes | None = None) -> bytes:
        """Sign a payload.

        Sends payload to device and retrieves the signature.

        For ML-DSA, the FIPS 204 external mu is computed using the message
        and public key: the mu is sent to device instead of payload.

        Note:
            This method blocks and waits (up to 60 seconds) for the user to touch
            the physical TKey device when it flashes.

        Args:
            message: The raw bytes of the message/payload to sign. When Ed25519 keys
                are used, there is a max message size of 4096B. This limitation does
                not apply to ML-DSA as FIPS 204 external mu is used.
            pub_key: The public key bytes (only needed for ML-DSA). If not provided,
                key is retrieved from device.

        Returns:
            The generated signature as raw bytes.

        Raises:
            TKeyError: If the device returns a bad status during signing.
            TKeyIOError: If writing or reading from the serial port fails.
            TKeyProtocolError: If there is a framing or protocol mismatch.
        """
        # pqsn = ML-DSA signer, pqnt = no-touch ML-DSA test signer
        if self.name in [("tk1", "pqsn"), ("tk1", "pqnt")]:
            # Compute FIPS 204 external mu
            if pub_key is None:
                pub_key = self.get_pubkey()
            tr = hashlib.shake_256(pub_key).digest(64)
            payload = hashlib.shake_256(tr + b"\x00\x00" + message).digest(64)
        else:
            payload = message

        # Set size
        if len(payload) > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large {len(payload)} > {MAX_PAYLOAD_SIZE}]")
        self.send(SignCmd.SET_SIZE, len(payload).to_bytes(4, byteorder="little"))

        # Load data in chunks
        chunk_size = 127
        offset = 0
        while offset < len(payload):
            chunk = payload[offset : offset + chunk_size]
            rx = self.send(SignCmd.LOAD_DATA, chunk)
            if rx[2] != 0:
                raise TKeyError(f"LoadData chunk NOK status: {rx[2]}")
            offset += chunk_size

        # Trigger signing (blocks waiting for touch) and read first frame
        rx = self.send(SignCmd.GET_SIG, timeout=60)

        # Read remaining frames
        signature = bytearray(self.sig_size)
        offset = 0

        while offset < self.sig_size:
            if rx[2] != 0:
                raise TKeyError(f"GetSig chunk NOK status: {rx[2]}")

            chunk_size = min(self.sig_size - offset, 126)
            signature[offset : offset + chunk_size] = rx[3 : 3 + chunk_size]
            offset += chunk_size

            if offset < self.sig_size:
                rx = self.recv_response(SignCmd.GET_SIG)

        return bytes(signature)
