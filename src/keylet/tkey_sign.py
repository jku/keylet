"""Keylet TKey signer implementation

This class implements a host application for a TKey signer. The design supports
a specific application protocol (see SignCmd)

The protocol and device binary are from
https://github.com/tillitis/tkey-pq-device-signer
"""

from __future__ import annotations

import hashlib
import importlib.resources
import logging
from dataclasses import dataclass

from keylet.tkey import Cmd, LenIdx, Rsp, TKey, TKeyError

logger = logging.getLogger(__name__)

MU_SIZE = (64).to_bytes(4, byteorder="little")


@dataclass
class SignApp:
    """Signapp represents the *device* signing application"""

    binary: bytes
    version: int
    name: tuple[str, str] = ("tk1", "pqsn")
    sig_size: int = 2420
    key_size: int = 1312

    @classmethod
    def load(cls, version: int = 3) -> SignApp:
        """Load embedded device signer application."""
        try:
            name = f"pqsigner_v{version}.bin"
            binary = (
                importlib.resources.files("keylet.resources")
                .joinpath(name)
                .read_bytes()
            )
            return cls(binary, version)
        except FileNotFoundError as e:
            raise ValueError(
                f"TKey device app v{version} not found in package resources"
            ) from e


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
    """Client for a TKey signer application"""

    def __init__(
        self,
        app: SignApp,
        device: str | None = None,
        secret: str | None = None,
    ) -> None:
        super().__init__(device)
        self.key_size = app.key_size
        self.sig_size = app.sig_size

        if not self.load_app(app.binary, secret):
            # TKey is not in firmware mode: Query application name and version
            rx = self.send(SignCmd.GET_NAMEVERSION)
            name = (rx[2:6].decode("ascii").rstrip(), rx[6:10].decode("ascii").rstrip())
            ver = int.from_bytes(rx[10:14], byteorder="little")
            if name == app.name and ver == app.version:
                return  # Signer application is already loaded

            raise TKeyError(
                f"TKey is running an unknown application {name, ver}, "
                f"expected {app.name, app.version}"
            )

    def get_pubkey(self) -> bytes:
        """Retrieve public key bytes from device in multiple frames."""
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
        """Sign message using ML-DSA. Computes FIPS 204 external mu."""
        if pub_key is None:
            pub_key = self.get_pubkey()

        # Compute FIPS 204 external mu
        tr = hashlib.shake_256(pub_key).digest(64)
        mu = hashlib.shake_256(tr + b"\x00\x00" + message).digest(64)

        # Set size: in our case mu is always 64 bytes
        self.send(SignCmd.SET_SIZE, MU_SIZE)

        # Load data: mu fits in single frame
        self.send(SignCmd.LOAD_DATA, mu)

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
