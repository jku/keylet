# keylet -- Client library for Tillitis TKey

[![keylet on GitHub](https://img.shields.io/badge/GitHub-jku%2Fkeylet-blue?logo=github)](https://github.com/jku/keylet) [![keylet on PyPI](https://img.shields.io/pypi/v/keylet.svg)](https://pypi.org/project/keylet/) [![keylet documentation](https://img.shields.io/badge/Documentation-blue)](https://jku.github.io/keylet/)

Keylet is a Python client library and CLI tool for the [Tillitis TKey](https://www.tillitis.se/products/tkey/) security token, and implements a ML-DSA signer application for TKey.

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

# When using keylet long-term, remember to specify device app digest (keylet default
# app version may change, but you will need a specific application to keep using the
# same key)
$ keylet --passphrase hunter2 --digest 186bcf6 sign README.md

```

## Library Usage

```python
from keylet import TKeySign, SignApp

# Load the default embedded ML-DSA signer
app = SignApp.load_mldsa()
digest = app.digest

# Initialize the signer with a passphrase
with TKeySign(app=app, secret="hunter2") as signer:
    # Sign a payload
    signature = signer.sign(b"my payload")
```

In long-term use, the device app digest should be used to ensure the same application
is always used for a specific key:

```python
# Load application with a digest stored earlier
app = SignApp.load_mldsa(digest=digest)

# Initialize the signer with a passphrase
with TKeySign(app=app, secret="hunter2") as signer:
    # Sign a payload
    signature = signer.sign(b"my payload")
```

See the [API Reference](https://jku.github.io/keylet/api/) for more details.
