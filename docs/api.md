# API Reference

This page documents the classes used for signing payloads with the Tillitis TKey. The common usage pattern is:

1. Construct device application configuration with `SignApp.load_mldsa()`
    - If this is the first use of the key, store the app digest
    - On subsequent uses, provide the same app digest to `load_mldsa()`
2. Initialize a `TKeySign` signer using the application configuration: this loads the application onto the device
3. Use the signer to sign payloads


## ML-DSA Signer

::: keylet.TKeySign

## Device Application Configuration

::: keylet.SignApp
