# keylet -- Client library for Tillitis TKey

[![keylet on GitHub](https://img.shields.io/badge/GitHub-jku%2Fkeylet-blue?logo=github)](https://github.com/jku/keylet) [![keylet on PyPI](https://img.shields.io/pypi/v/keylet.svg)](https://pypi.org/project/keylet/) [![keylet documentation](https://img.shields.io/badge/Documentation-blue)](https://jku.github.io/keylet/)

Keylet is a Python client library and CLI tool for the [Tillitis TKey](https://www.tillitis.se/products/tkey/) security token, and implements a ML-DSA / Ed25519 signer application for TKey.

TKeys unique feature is that it has no long-term memory: signing keys are _always_ generated from a seed at runtime. This seed is built by combining a Unique Device Secret, a Device Application hash and an optional User Supplied Secret. Both the Device Application and User Supplied Secret are provided at runtime by `keylet`. 

The unique design leads to some API peculiarities:

* User Supplied Secret (passphrase) is not directly validated by keylet: a "wrong" passphrase will just lead to using a different signing key. In practice the calling application should look at `TKeySign.get_pubkey()`: if the key is unexpected, then potentially the wrong passphrase was used.
* In long-term use (where the same signing key is expected to be used over a period of time) the calling application is responsible for always selecting the same Device Application: `keylet` provides a mechanism for this, see examples.
* The only way to change the device application or passphrase after initialization is to unplug the device and start over.
* Signer initialization has an optimization where the initialization succeeds if the TKey has already been initialized with matching device application name and version. Unfortunately `keylet` cannot confirm that the exact device binary is the expected one or that the passphrase is still the same one (but again, the calling application can compare `TKeySign.get_pubkey()` to the expected key)

## Installation

```bash
pip install keylet
```

## CLI Usage

The package installs a `keylet` command-line tool for signing and verification. This is primarily a test/demo application for the library.

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

## Development

[uv](https://docs.astral.sh/uv/) is a required development tool.

```bash
# Run keylet CLI from source
uv run keylet sign README.md

# run linters and type checker
make lint

# Fix formatting and lint issues
make fix

# run tests
make test

# run tests, including on-device tests
make test-device
```
