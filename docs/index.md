# Keylet

[![keylet on PyPI](https://img.shields.io/pypi/v/keylet.svg)](https://pypi.org/project/keylet/) [![GitHub](https://img.shields.io/badge/GitHub-jku%2Fkeylet-blue?logo=github)](https://github.com/jku/keylet)

Keylet is a Python client library and CLI tool for the Tillitis TKey hardware cryptographic key, specifically supporting the ML-DSA signer application.

## Installation

```bash
pip install keylet
```

## CLI Usage

The package installs a `keylet` command-line tool for quick signing and verification.

```bash
# Sign without a passphrase, then verify
$ keylet sign README.md
$ keylet verify README.md

# Get public key, sign with a passphrase, and verify using the saved public key
$ keylet --passphrase hunter2 pubkey --output pub.key
$ keylet --passphrase hunter2 sign README.md
$ keylet verify --pubkey pub.key README.md
```

## Library Usage

```python
from keylet import TKeySign, SignApp

# Load the default embedded ML-DSA signer
app = SignApp.load_mldsa()

# Initialize the signer with a passphrase
with TKeySign(app=app, secret="hunter2") as signer:
    # Sign a payload
    signature = signer.sign(b"my payload")
```

See the [API Reference](api.md) for more details.
