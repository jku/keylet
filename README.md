## Keylet -- Client library for Tillitis TKey

This library provides a client implementation for the Tillitis TKey, and specifically
the [tkey-pq-device-signer](https://github.com/tillitis/tkey-pq-device-signer) application.

### CLI Example

```bash
# Sign without a passphrase, verify
$ keylet sign README.md
$ keylet verify README.md

# Store pubkey, sign with passphrase, verify
$ keylet --passphrase hunter2 pubkey --output pub.key
$ keylet --passphrase hunter2 sign README.md
$ keylet verify --pubkey pub.key README.md
```

### API Example

```python
from keylet import TKeySign, SignApp

binary = open("pqsigner_v3.bin", "rb").read()
signer = TKeySign(app=SignApp(binary, 3), secret="hunter2")

sig = signer.sign(b"payload")
