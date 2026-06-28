# SPDX-License-Identifier: MIT
# Copyright (c) 2026 keylet authors

import hashlib
import unittest
from unittest.mock import MagicMock, patch

from keylet.tkey import (
    PROTO_DATA_LENGTH,
    FwCmd,
    FwRsp,
    Rsp,
    TKey,
    TKeyProtocolError,
)
from keylet.tkey_sign import SignApp, SignRsp, TKeySign


def make_response_frame(
    fid: int,
    eid: int,
    status: int,
    rsp: Rsp,
    data: bytes = b"",
) -> bytes:
    header = (fid << 5) | (eid << 3) | (status << 2) | rsp.len_idx
    resp_len = PROTO_DATA_LENGTH[rsp.len_idx]
    resp_data = bytearray(resp_len)
    resp_data[0] = rsp.id
    if data:
        resp_data[1 : 1 + len(data)] = data
    return bytes([header]) + bytes(resp_data)


class MockStreamConnection:
    def __init__(self, reads: list[bytes]) -> None:
        self.reads = reads
        self.written = bytearray()
        self.timeout = 5.0

    def write(self, data: bytes) -> int:
        self.written.extend(data)
        return len(data)

    def read(self, n: int) -> bytes:
        if not self.reads:
            return b""
        block = self.reads[0]
        chunk = block[:n]
        if len(chunk) == len(block):
            self.reads.pop(0)
        else:
            self.reads[0] = block[n:]
        return chunk

    def close(self) -> None:
        pass

    @property
    def in_waiting(self) -> int:
        return sum(len(b) for b in self.reads)


class TestTKey(unittest.TestCase):
    @patch.object(TKey, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKey, "_get_connection")
    def test_tkey_init_and_disconnect(
        self, mock_get_connection: MagicMock, mock_find_device: MagicMock
    ) -> None:
        mock_conn = MagicMock()
        mock_get_connection.return_value = mock_conn

        tkey = TKey(device=None)
        mock_find_device.assert_called_once_with(None)
        mock_get_connection.assert_called_once_with(
            "/dev/ttyACM0", baudrate=62500, timeout=5.0
        )

        tkey.disconnect()
        mock_conn.close.assert_called_once()

    @patch.object(TKey, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKey, "_get_connection")
    def test_send_and_recv_protocol(
        self, mock_get_connection: MagicMock, mock_find_device: MagicMock
    ) -> None:
        # Expected response: NAME_VERSION firmware response
        fw_name_payload = b"tk1 " + b"mkdf"
        # Frame ID sequence starts at 0, next_fid() will return 1
        expected_response = make_response_frame(
            fid=1,
            eid=2,
            status=0,
            rsp=FwRsp.NAME_VERSION,
            data=fw_name_payload,
        )

        mock_conn = MockStreamConnection(reads=[expected_response])
        mock_get_connection.return_value = mock_conn

        tkey = TKey(device=None)
        response = tkey.send(FwCmd.NAME_VERSION)

        # Verify response parsing
        self.assertEqual(response[1], FwRsp.NAME_VERSION.id)
        self.assertEqual(response[2:6], b"tk1 ")
        self.assertEqual(response[6:10], b"mkdf")

        # Verify what was written
        written = bytes(mock_conn.written)
        self.assertEqual(len(written), 2)  # Header (1 byte) + Cmd ID (1 byte)
        # Header: (FID=1 << 5) | (EID=2 << 3) | LenIdx=0 -> 32 | 16 | 0 = 48 (0x30)
        self.assertEqual(written[0], 0x30)
        self.assertEqual(written[1], FwCmd.NAME_VERSION.id)

    @patch.object(TKey, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKey, "_get_connection")
    def test_send_protocol_error_status(
        self, mock_get_connection: MagicMock, mock_find_device: MagicMock
    ) -> None:
        # Response with status NOK (1)
        nok_response = make_response_frame(
            fid=1,
            eid=2,
            status=1,
            rsp=FwRsp.NAME_VERSION,
        )

        mock_conn = MockStreamConnection(reads=[nok_response])
        mock_get_connection.return_value = mock_conn

        tkey = TKey(device=None)
        with self.assertRaises(TKeyProtocolError) as ctx:
            tkey.send(FwCmd.NAME_VERSION)
        self.assertIn("Response status code not OK", str(ctx.exception))


class TestTKeySign(unittest.TestCase):
    @patch.object(TKeySign, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKeySign, "_get_connection")
    def test_load_app_and_sign_flow(
        self, mock_get_connection: MagicMock, mock_find_device: MagicMock
    ) -> None:
        app_binary = b"fake_app_binary_data"
        app_digest = hashlib.blake2s(app_binary, digest_size=32).digest()

        # Responses sequence:
        # 1. NAME_VERSION (during load_app to check if in FW mode)
        fw_response = make_response_frame(
            fid=1, eid=2, status=0, rsp=FwRsp.NAME_VERSION, data=b"tk1 " + b"mkdf"
        )
        # 2. LOAD_APP response
        load_app_response = make_response_frame(
            fid=2, eid=2, status=0, rsp=FwRsp.LOAD_APP, data=b"\x00"
        )
        # 3. LOAD_APP_DATA response (final chunk status indicating ready)
        load_app_data_response = make_response_frame(
            fid=3,
            eid=2,
            status=0,
            rsp=FwRsp.LOAD_APP_DATA_READY,
            data=b"\x00" + app_digest,
        )

        mock_conn = MockStreamConnection(
            reads=[fw_response, load_app_response, load_app_data_response]
        )
        mock_get_connection.return_value = mock_conn

        # Instantiate TKeySign (this triggers load_app since it starts in FW mode)
        app = SignApp(binary=app_binary, version=1, key_size=128, sig_size=64)
        tkeysign = TKeySign(app=app, device=None)

        # Verify that it loaded successfully
        self.assertEqual(tkeysign.key_size, 128)
        self.assertEqual(tkeysign.sig_size, 64)

        # Now test get_pubkey
        # The key size is 128. Since each GET_PUBKEY response frame carries
        # up to 127 bytes, it will take 2 frames to read 128 bytes.
        pubkey_part1 = b"A" * 127
        pubkey_part2 = b"B" * 1

        pubkey_response_1 = make_response_frame(
            fid=0, eid=3, status=0, rsp=SignRsp.GET_PUBKEY, data=pubkey_part1
        )
        pubkey_response_2 = make_response_frame(
            fid=0, eid=3, status=0, rsp=SignRsp.GET_PUBKEY, data=pubkey_part2
        )

        mock_conn.reads.extend([pubkey_response_1, pubkey_response_2])
        pubkey = tkeysign.get_pubkey()
        self.assertEqual(pubkey, pubkey_part1 + pubkey_part2)

        # Now test sign
        # We need to mock the responses for:
        # 1. SET_SIZE response
        # 2. LOAD_DATA response
        # 3. GET_SIG response (signature size 64 fits in one 126-byte chunk)
        sig_data = b"S" * 64
        set_size_resp = make_response_frame(
            fid=1, eid=3, status=0, rsp=SignRsp.SET_SIZE, data=b"\x00"
        )
        load_data_resp = make_response_frame(
            fid=2, eid=3, status=0, rsp=SignRsp.LOAD_DATA, data=b"\x00"
        )
        # Note: SignRsp.GET_SIG response frame uses 1st byte as status in
        # payload (rx[2] != 0 check)
        get_sig_resp = make_response_frame(
            fid=3, eid=3, status=0, rsp=SignRsp.GET_SIG, data=b"\x00" + sig_data
        )

        mock_conn.reads.extend([set_size_resp, load_data_resp, get_sig_resp])
        signature = tkeysign.sign(b"test message", pub_key=pubkey)
        self.assertEqual(signature, sig_data)

    @patch.object(TKeySign, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKeySign, "_get_connection")
    def test_load_app_hashes_secret(
        self, mock_get_connection: MagicMock, mock_find_device: MagicMock
    ) -> None:
        """Test verifies that we do not accidentally change the load app content
        as it could change key derivation on device."""
        # Set up responses for:
        # 1. NAME_VERSION (FW mode check)
        # 2. LOAD_APP
        # 3. LOAD_APP_DATA (only one chunk because file size is small)
        fw_name_payload = b"tk1 " + b"mkdf"
        fw_response = make_response_frame(
            fid=1,
            eid=2,
            status=0,
            rsp=FwRsp.NAME_VERSION,
            data=fw_name_payload,
        )

        load_app_response = make_response_frame(
            fid=2,
            eid=2,
            status=0,
            rsp=FwRsp.LOAD_APP,
            data=b"\x00",
        )

        file_digest = hashlib.blake2s(b"mock_app_data", digest_size=32).digest()
        load_app_data_response = make_response_frame(
            fid=3,
            eid=2,
            status=0,
            rsp=FwRsp.LOAD_APP_DATA_READY,
            data=b"\x00" + file_digest,
        )

        mock_conn = MockStreamConnection(
            reads=[fw_response, load_app_response, load_app_data_response]
        )
        mock_get_connection.return_value = mock_conn

        secret = "my_super_secret_passphrase"
        app = SignApp(binary=b"mock_app_data", version=3, key_size=128, sig_size=64)
        tk = TKeySign(app=app, device=None, secret=secret)
        tk.disconnect()

        # Extract the written bytes to inspect the LOAD_APP command frame payload
        written_bytes = bytes(mock_conn.written)

        # First frame (NAME_VERSION): Header (1 byte) + Cmd ID (1 byte) = 2 bytes
        # Second frame (LOAD_APP): Header (1 byte) + Cmd ID (1 byte) +
        # Payload (127 bytes) = 129 bytes
        load_app_frame = written_bytes[2 : 2 + 129]

        self.assertEqual(
            load_app_frame[0], 0x53
        )  # FID=2, EID=2, Status=0, LenIdx=3 -> 0x53
        self.assertEqual(load_app_frame[1], FwCmd.LOAD_APP.id)

        # Verify the payload contents
        payload = load_app_frame[2:]
        # Size (4 bytes, little endian)
        self.assertEqual(payload[0:4], (13).to_bytes(4, byteorder="little"))
        # Passphrase enabled flag (1 byte)
        self.assertEqual(payload[4], 1)
        # Hashed passphrase (32 bytes)
        expected_hashed_secret = hashlib.blake2s(
            secret.encode("utf-8"), digest_size=32
        ).digest()
        self.assertEqual(payload[5 : 5 + 32], expected_hashed_secret)

    @patch("importlib.resources.files")
    @patch("keylet.tkey_sign._EMBEDDED_MLDSA_BINS", new_callable=list)
    def test_sign_app_load_by_digest(
        self,
        mock_embedded: list[tuple[str, int, tuple[str, str]]],
        mock_files: MagicMock,
    ) -> None:
        bin0 = b"binary_zero_data"
        bin1 = b"binary_one_data"
        bin2 = b"binary_two_data"

        digest0 = hashlib.blake2s(bin0, digest_size=32).hexdigest()
        digest1 = hashlib.blake2s(bin1, digest_size=32).hexdigest()
        digest2 = hashlib.blake2s(bin2, digest_size=32).hexdigest()

        # Configure the mock registry
        mock_embedded.clear()
        mock_embedded.extend(
            [
                ("pqsigner_v3.bin", 3, ("tk1", "pqsn")),
                ("pqsigner_v3_first.bin", 3, ("tk1", "pqsn")),
                ("pqsigner_v4_second.bin", 4, ("tk1", "pqsn")),
            ]
        )

        # Mock joinpath().read_bytes()
        mock_dir = MagicMock()
        mock_file0 = MagicMock()
        mock_file0.read_bytes.return_value = bin0
        mock_file1 = MagicMock()
        mock_file1.read_bytes.return_value = bin1
        mock_file2 = MagicMock()
        mock_file2.read_bytes.return_value = bin2

        def joinpath_side_effect(filename: str) -> MagicMock:
            if filename == "pqsigner_v3.bin":
                return mock_file0
            if filename == "pqsigner_v3_first.bin":
                return mock_file1
            if filename == "pqsigner_v4_second.bin":
                return mock_file2
            raise FileNotFoundError()

        mock_dir.joinpath.side_effect = joinpath_side_effect
        mock_files.return_value = mock_dir

        # Test loading default
        app0 = SignApp.load_mldsa()
        self.assertEqual(app0.binary, bin0)
        self.assertEqual(app0.version, 3)
        self.assertEqual(app0.digest, digest0)

        # Test loading by exact digest
        app1 = SignApp.load_mldsa(digest=digest1)
        self.assertEqual(app1.binary, bin1)
        self.assertEqual(app1.version, 3)
        self.assertEqual(app1.digest, digest1)

        # Test loading by prefix
        app2 = SignApp.load_mldsa(digest=digest2[:8])
        self.assertEqual(app2.binary, bin2)
        self.assertEqual(app2.version, 4)

        # Test not found
        with self.assertRaises(ValueError) as ctx:
            SignApp.load_mldsa(digest="nonexistent")
        self.assertIn("No device binary found matching", str(ctx.exception))

        # Test version mismatch
        with self.assertRaises(ValueError) as ctx:
            SignApp.load_mldsa(version=3, digest=digest2)
        self.assertIn("No device binary found matching", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
