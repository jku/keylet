import argparse
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PublicKey

from keylet.tkey import TKeyNotFoundError
from keylet.tkey_sign import SignApp, TKeySign


def get_signer(device: str | None, passphrase: str | None) -> TKeySign:
    """Helper to initialize TKeySign with the default device signer binary."""
    app = SignApp.load()
    return TKeySign(app, device=device, secret=passphrase)


def cmd_pubkey(args: argparse.Namespace) -> int:
    try:
        with get_signer(args.device, args.passphrase) as signer:
            pubkey = signer.get_pubkey()
            if args.output:
                Path(args.output).write_bytes(pubkey)
                print(f"Public key written to {args.output}")
            else:
                print(pubkey.hex())
            return 0
    except TKeyNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_sign(args: argparse.Namespace) -> int:
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File {args.file} does not exist", file=sys.stderr)
        return 1

    try:
        data = file_path.read_bytes()
        with get_signer(args.device, args.passphrase) as signer:
            print("Please touch the TKey device when it flashes to sign...")
            signature = signer.sign(data)

            sig_path = file_path.with_suffix(file_path.suffix + ".signature")
            sig_path.write_bytes(signature)
            print(f"Signature written to {sig_path}")
            return 0
    except TKeyNotFoundError as e:
        print(f"Signing failed: {e}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File {args.file} does not exist", file=sys.stderr)
        return 1

    sig_path = (
        Path(args.signature)
        if args.signature
        else file_path.with_suffix(file_path.suffix + ".signature")
    )
    if not sig_path.exists():
        print(f"Error: Signature file {sig_path} does not exist", file=sys.stderr)
        return 1

    try:
        file_bytes = file_path.read_bytes()
        sig_bytes = sig_path.read_bytes()

        # Get public key either from file or from device
        if args.pubkey:
            pubkey_bytes = Path(args.pubkey).read_bytes()
        else:
            print("Retrieving public key from device...")
            with get_signer(args.device, args.passphrase) as signer:
                pubkey_bytes = signer.get_pubkey()

        # Verify signature using cryptography library
        pubkey = MLDSA44PublicKey.from_public_bytes(pubkey_bytes)
        pubkey.verify(sig_bytes, file_bytes)
        print("Verification successful!")
        return 0
    except InvalidSignature:
        print("Verification failed: Invalid signature", file=sys.stderr)
        return 1
    except TKeyNotFoundError as e:
        print(f"Verification failed: {e}", file=sys.stderr)
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tillitis TKey Keylet CLI testing tool"
    )
    parser.add_argument(
        "--device", help="Serial port of the TKey device (e.g. /dev/ttyACM0)"
    )
    parser.add_argument("--passphrase", help="User Supplied Secret (passphrase)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # pubkey command
    parser_pubkey = subparsers.add_parser("pubkey", help="Get public key from device")
    parser_pubkey.add_argument(
        "-o", "--output", help="Output file to write public key to"
    )

    # sign command
    parser_sign = subparsers.add_parser("sign", help="Sign a file")
    parser_sign.add_argument("file", help="File to sign")

    # verify command
    parser_verify = subparsers.add_parser("verify", help="Verify a signature")
    parser_verify.add_argument("file", help="File that was signed")
    parser_verify.add_argument(
        "--signature", help="Signature file (defaults to <FILE>.signature)"
    )
    parser_verify.add_argument(
        "--pubkey", help="Public key file (retrieved from device if not specified)"
    )

    args = parser.parse_args()

    if args.command == "pubkey":
        sys.exit(cmd_pubkey(args))
    elif args.command == "sign":
        sys.exit(cmd_sign(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))


if __name__ == "__main__":
    main()
