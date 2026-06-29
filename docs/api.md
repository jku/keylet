# API Reference

This page documents the classes used for signing payloads with the Tillitis TKey. The common usage pattern is:

1. Construct device application configuration with `SignApp.load_mldsa()` or `SignApp.load_ed25519()`
    - If this is the first use of the key, store the app digest
    - On subsequent uses, provide the same app digest to `load_mldsa()` or `load_ed25519()`
2. Initialize a `TKeySign` signer using the application configuration: this loads the application onto the device
3. Use the signer to sign payloads


## TKey Signer Client

::: keylet.TKeySign

## Device Application Configuration

::: keylet.SignApp
