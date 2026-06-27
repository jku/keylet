# SPDX-License-Identifier: MIT
# Copyright (c) 2026 keylet authors

from __future__ import annotations

import hashlib
import logging
import sys
from dataclasses import dataclass
from types import TracebackType
from typing import TypeVar

import serial
from serial.tools import list_ports

from keylet._serial_hack import (
    RawSerialConnection,
    SerialConnection,
)

logger = logging.getLogger(__name__)

# USB Vendor & Product ID for TKey
TKEY_USB_VID = 0x1207
TKEY_USB_PID = 0x8887

# Maximum size for applications to load onto TKey (100 KiB)
APP_MAXSIZE = 100 * 1024


# Data lengths corresponding to header length bits (0, 1, 2, 3)
PROTO_DATA_LENGTH = [1, 4, 32, 128]


# Length indices mapping to PROTO_DATA_LENGTH
class LenIdx:
    I1 = 0
    """1-byte payload length index."""
    I4 = 1
    """4-byte payload length index."""
    I32 = 2
    """32-byte payload length index."""
    I128 = 3
    """128-byte payload length index."""


@dataclass(frozen=True)
class Rsp:
    """Protocol response definition.

    Attributes:
        id: The response identifier byte.
        len_idx: The length index indicating the expected data size.
    """
    id: int
    len_idx: int


@dataclass(frozen=True)
class Cmd:
    """Protocol command definition.

    Attributes:
        id: The command identifier byte.
        endpoint: The target endpoint on the device.
        len_idx: The length index indicating the payload data size.
        valid_responses: A tuple of acceptable responses for this command.
    """
    id: int
    endpoint: int
    len_idx: int
    valid_responses: tuple[Rsp, ...]


class FwRsp:
    """Firmware responses"""

    NAME_VERSION = Rsp(0x02, LenIdx.I32)
    """Response containing firmware name and version."""
    LOAD_APP = Rsp(0x04, LenIdx.I4)
    """Response indicating the application loading status."""
    LOAD_APP_DATA = Rsp(0x06, LenIdx.I4)
    """Response indicating the application data chunk status."""
    LOAD_APP_DATA_READY = Rsp(0x07, LenIdx.I128)
    """Response indicating all application data has been received and verified."""


class FwCmd:
    """Firmware commands"""

    NAME_VERSION = Cmd(0x01, 2, LenIdx.I1, (FwRsp.NAME_VERSION,))
    """Command to query the firmware name and version."""
    LOAD_APP = Cmd(0x03, 2, LenIdx.I128, (FwRsp.LOAD_APP,))
    """Command to initiate application loading with size and optional secret."""
    LOAD_APP_DATA = Cmd(
        0x05, 2, LenIdx.I128, (FwRsp.LOAD_APP_DATA, FwRsp.LOAD_APP_DATA_READY)
    )
    """Command to send a chunk of application binary data."""


_TKey = TypeVar("_TKey", bound="TKey")


class TKeyError(Exception):
    """Base class for TKey errors."""


class TKeyNotFoundError(TKeyError):
    """A TKey device was not found"""


class TKeyAppError(TKeyError):
    """Raised when loading the application fails."""


class TKeyIOError(TKeyError):
    """Raised when read/write fails."""


class TKeyProtocolError(TKeyError):
    """Raised upon protocol errors in command or response."""


class TKey:
    """Base TKey Client

    TKey is used to build host (client) applications for a Tillitis TKey.
    It implements the Firmware protocol and provides serial IO as well
    as some helpers for the actual application implementation.

    Links:

    * [Framing protocol](https://dev.tillitis.se/protocol/#framing-protocol)
    """

    def __init__(
        self,
        device: str | None,
    ) -> None:
        """Initialize serial connection to TKey device.

        Args:
            device: Optional serial port path (e.g., `/dev/ttyACM0`). If None,
                the port is auto-detected.

        Raises:
            TKeyNotFoundError: If no TKey device is found.
            TKeyError: If the serial connection fails to open.
        """

        self._conn: SerialConnection | None = None
        self._fid = 0

        port = self._find_device(device)
        self._conn = self._get_connection(port, baudrate=62500, timeout=5.0)

    @staticmethod
    def _find_device(device_path: str | None) -> str:
        """Discover TKey device serial port using pyserial."""

        ports = list_ports.comports()
        devices = sorted(
            p.device for p in ports if p.vid == TKEY_USB_VID and p.pid == TKEY_USB_PID
        )

        if device_path is None:
            if not devices:
                raise TKeyNotFoundError("No TKey devices found")
            device_path = devices[0]
        elif device_path not in devices:
            raise TKeyNotFoundError(f"TKey device {device_path} not found")
        return device_path

    def _get_connection(
        self, port: str, baudrate: int, timeout: float
    ) -> SerialConnection:
        if sys.platform == "linux":
            return RawSerialConnection(port, baudrate, timeout)
        else:
            try:
                return serial.Serial(port, baudrate=baudrate, timeout=timeout)
            except Exception as e:
                raise TKeyError(f"Failed to open serial port {port}: {e}") from e

    def disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception as e:
                logger.debug("Failed to close TKey connection: %s", e)
            self._conn = None

    def __del__(self) -> None:
        self.disconnect()

    def __enter__(self: _TKey) -> _TKey:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.disconnect()

    def _next_fid(self) -> int:
        """Returns a frame id (rotating sequence [0-3])"""
        self._fid = (self._fid + 1) % 4
        return self._fid

    def send(self, cmd: Cmd, data: bytes = b"", timeout: int = -1) -> bytes:
        """Frame and send a command, then read the first response frame.

        Caller is expected to call recv_response() if the response is longer than one
        frame.

        Args:
            cmd: The command to send.
            data: Optional payload data for the command.
            timeout: Optional serial timeout in seconds. If -1, the default
                connection timeout is used.

        Returns:
            The first response frame as bytes.

        Raises:
            TKeyError: If the TKey is not connected.
            TKeyProtocolError: If the data exceeds the command's maximum length.
            TKeyIOError: If writing the frame fails.
        """
        if self._conn is None:
            raise TKeyError("TKey is not connected")

        old_timeout = self._conn.timeout
        if timeout >= 0:
            self._conn.timeout = timeout
        try:
            return self._send(cmd, data)
        finally:
            if timeout >= 0:
                self._conn.timeout = old_timeout

    def _send(self, cmd: Cmd, data: bytes = b"") -> bytes:
        if self._conn is None:
            raise TKeyError("TKey is not connected")

        fid = self._next_fid()

        expected_len = PROTO_DATA_LENGTH[cmd.len_idx]
        if len(data) > expected_len - 1:
            raise TKeyProtocolError("Data exceeds command data length in header")

        header = (fid << 5) | (cmd.endpoint << 3) | cmd.len_idx
        frame = bytearray(1 + expected_len)
        frame[0] = header
        frame[1] = cmd.id
        if data:
            frame[2 : 2 + len(data)] = data

        try:
            self._conn.write(bytes(frame))
        except Exception as e:
            raise TKeyIOError(f"Failed to write frame: {e}") from e

        return self.recv_response(cmd)

    def recv_response(self, cmd: Cmd) -> bytes:
        """Receive and return a response frame.

        `recv_response()` can only be called if there are unread frames from a previous
        `send()` call for the given command.

        Args:
            cmd: The command that this response is for.

        Returns:
            The response frame as bytes.

        Raises:
            TKeyError: If the TKey is not connected.
            TKeyIOError: If reading the response from the serial port fails or returns no data.
            TKeyProtocolError: If the response status is not OK, the response length is invalid,
                the frame ID/endpoint mismatch, or the response ID is unexpected.
        """
        if self._conn is None:
            raise TKeyError("TKey is not connected")

        try:
            resp_header_byte = self._conn.read(1)
        except Exception as e:
            raise TKeyIOError(f"Failed to read response header: {e}") from e

        if not resp_header_byte:
            raise TKeyIOError("No response data")

        header_val = resp_header_byte[0]
        resp_fid = (header_val >> 5) & 3
        resp_eid = (header_val >> 3) & 3
        resp_status = (header_val >> 2) & 1
        resp_len_idx = header_val & 3
        resp_len = PROTO_DATA_LENGTH[resp_len_idx]

        if resp_status == 1:
            try:
                self._conn.read(resp_len)
            except Exception as e:
                logger.debug("Failed to read remaining bytes after NOK status: %s", e)
            raise TKeyProtocolError("Response status code not OK (1)")

        try:
            resp_data = self._conn.read(resp_len)
        except Exception as e:
            raise TKeyIOError(f"Failed to read response data: {e}") from e

        if len(resp_data) != resp_len:
            raise TKeyProtocolError("Unexpected response data length")

        # Validate frame ID and endpoint
        if resp_fid != self._fid or resp_eid != cmd.endpoint:
            raise TKeyProtocolError(
                f"Response mismatch: expected Frame ID {self._fid} and Endpoint "
                f"{cmd.endpoint}, got Frame ID {resp_fid} and Endpoint {resp_eid}"
            )

        rsp = Rsp(resp_data[0], resp_len_idx)
        if rsp not in cmd.valid_responses:
            raise TKeyProtocolError(
                f"Unexpected protocol response for cmd {cmd.id:#x} on endpoint "
                f"{cmd.endpoint}: response={rsp.id:#x}, len_index={rsp.len_idx}"
            )

        response = bytearray(1 + resp_len)
        response[0] = header_val
        response[1:] = resp_data
        return bytes(response)

    def load_app(self, app_binary: bytes, secret: str | None = None) -> bool:
        """Load an application binary into the TKey device.

        Args:
            app_binary: The raw bytes of the application binary.
            secret: Optional User Supplied Secret (passphrase) to configure the app with.

        Returns:
            True if the application was successfully loaded, False if the
                device was not in firmware mode (i.e. already running an application).

        Raises:
            TKeyAppError: If the binary is too large, the device is not ready,
                or the loaded app's digest does not match the local digest.
            TKeyError: If the device is running an unknown firmware or if loading
                data fails.
        """
        file_size = len(app_binary)
        if file_size > APP_MAXSIZE:
            raise TKeyAppError(
                f"Application binary is too large ({file_size} > {APP_MAXSIZE})"
            )

        try:
            # Query firmware name
            rx = self.send(FwCmd.NAME_VERSION)
        except TKeyError:
            # Not in firmware mode
            # TODO would be nice to only do this on NOK response, not other errors
            return False

        # we are in firmware mode. Load the app
        fw_name0 = rx[2:6].decode("ascii").rstrip()
        fw_name1 = rx[6:10].decode("ascii").rstrip()
        if fw_name0 != "tk1" or fw_name1 != "mkdf":
            raise TKeyError(f"TKey is running an unknown firmware {fw_name0, fw_name1}")

        file_digest = hashlib.blake2s(app_binary, digest_size=32).digest()

        data = bytearray(127)
        data[0:4] = file_size.to_bytes(4, byteorder="little")
        if secret is not None:
            data[4] = 1
            uss = hashlib.blake2s(secret.encode("utf-8"), digest_size=32)
            data[5 : 5 + 32] = uss.digest()

        response = self.send(FwCmd.LOAD_APP, bytes(data))
        if response[2] == 1:
            raise TKeyAppError("Device not ready (STATUS_BAD)")

        result_digest = self._load_app_data(app_binary)
        if file_digest != result_digest:
            raise TKeyAppError(
                "App digest does not match "
                f"({file_digest.hex()} != {result_digest.hex()})"
            )

        if self._conn and self._conn.in_waiting:
            self._conn.read(self._conn.in_waiting)

        return True

    def _load_app_data(self, file_data: bytes) -> bytes:
        digest = b""
        offset = 0
        while offset < len(file_data):
            chunk = file_data[offset : offset + 127]
            response = self.send(FwCmd.LOAD_APP_DATA, chunk)
            response_id = response[1]
            status = response[2]
            if status == 1:
                raise TKeyError("Bad status when writing app data")

            if response_id == FwRsp.LOAD_APP_DATA_READY.id:
                digest = response[3:35]

            offset += 127

        return digest
