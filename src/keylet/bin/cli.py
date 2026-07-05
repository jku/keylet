# SPDX-License-Identifier: MIT
# Copyright (c) 2026 keylet authors

import argparse
import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PublicKey

from keylet.tkey import TKeyNotFoundError, TKeyUnexpectedAppError
from keylet.tkey_sign import SignApp, TKeySign


@contextmanager
def _app_signer(args: argparse.Namespace) -> Generator[TKeySign, None, None]:
    try:
        if args.type == "ed25519":
            app = SignApp.load_ed25519(digest=args.digest)
        else:
            app = SignApp.load_mldsa(digest=args.digest)
        with TKeySign(app, secret=args.passphrase) as signer:
            print(f"Using {args.type} device app with digest {app.digest[:7]}")
            yield signer
    except TKeyNotFoundError as e:
        sys.exit(f"Error: {e}")
    except TKeyUnexpectedAppError as e:
        sys.exit(f"Error: {e}")


def cmd_pubkey(args: argparse.Namespace) -> None:
    with _app_signer(args) as signer:
        pubkey = signer.get_pubkey()
    if args.output:
        Path(args.output).write_bytes(pubkey)
        print(f"Public key written to {args.output}")
    else:
        print(pubkey.hex())


def cmd_sign(args: argparse.Namespace) -> None:
    file_path = Path(args.file)
    if not file_path.exists():
        sys.exit(f"Error: File {args.file} does not exist")

    data = file_path.read_bytes()
    with _app_signer(args) as signer:
        print("Please touch the TKey device when it flashes to sign...")
        signature = signer.sign(data)

    sig_path = file_path.with_suffix(file_path.suffix + ".signature")
    sig_path.write_bytes(signature)
    print(f"Signature written to {sig_path}")


def cmd_verify(args: argparse.Namespace) -> None:
    file_path = Path(args.file)
    if not file_path.exists():
        sys.exit(f"Error: File {args.file} does not exist")

    sig_path = (
        Path(args.signature)
        if args.signature
        else file_path.with_suffix(file_path.suffix + ".signature")
    )
    if not sig_path.exists():
        sys.exit(f"Error: Signature file {sig_path} does not exist")

    file_bytes = file_path.read_bytes()
    sig_bytes = sig_path.read_bytes()

    # Get public key either from file or from device
    if args.pubkey:
        pubkey_bytes = Path(args.pubkey).read_bytes()
    else:
        with _app_signer(args) as signer:
            print("Retrieving public key from device...")
            pubkey_bytes = signer.get_pubkey()

    try:
        # Verify signature using cryptography
        if args.type == "ed25519":
            ed_pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            ed_pubkey.verify(sig_bytes, file_bytes)
        else:
            ml_pubkey = MLDSA44PublicKey.from_public_bytes(pubkey_bytes)
            ml_pubkey.verify(sig_bytes, file_bytes)
    except InvalidSignature:
        sys.exit("Verification failed: Invalid signature")

    print("Verification successful!")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="keylet -- Signing tool for Tillitis TKey"
    )
    parser.add_argument(
        "--digest", help="Optional digest of the device application to use"
    )
    parser.add_argument("--passphrase")
    parser.add_argument(
        "-t",
        "--type",
        choices=["ml-dsa", "ed25519"],
        default="ml-dsa",
        help="key type (default: %(default)s)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # pubkey command
    parser_pubkey = subparsers.add_parser("pubkey", help="Get public key from device")
    parser_pubkey.add_argument("-o", "--output", help="File to write public key to")

    # sign command
    parser_sign = subparsers.add_parser("sign", help="Sign a file")
    parser_sign.add_argument("file", help="File to sign")

    # verify command
    parser_verify = subparsers.add_parser("verify", help="Verify a signature")
    parser_verify.add_argument("file", help="File to verify")
    parser_verify.add_argument(
        "--signature", help="Signature file (defaults to <FILE>.signature)"
    )
    parser_verify.add_argument(
        "--pubkey",
        help="Optional public key file (retrieved from device if not specified)",
    )

    args = parser.parse_args()

    if args.command == "pubkey":
        cmd_pubkey(args)
    elif args.command == "sign":
        cmd_sign(args)
    elif args.command == "verify":
        cmd_verify(args)


if __name__ == "__main__":
    main()
