## Keylet -- Client library for Tillitis TKey

This library provides a client implementation for the Tillitis TKey, and specifically
the [tkey-pq-device-signer](https://github.com/tillitis/tkey-pq-device-signer) application.

### Example

```python
from keylet import TKeySign, SignApp

binary = open("pqsigner_v3.bin", "rb").read()
signer = TKeySign(app=SignApp(binary, 3), secret="hunter2")

sig = signer.sign(b"payload")
