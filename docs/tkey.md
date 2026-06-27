# Low-Level TKey Protocol

This page documents the lower-level protocol, framing classes, and exception hierarchy of the `keylet` library. These are useful if you want to implement custom host applications or interact with the TKey firmware directly.

## Base TKey Client

::: keylet.tkey.TKey
    options:
      members:
        - __init__
        - send
        - recv_response
        - load_app
        - disconnect

## Protocol Structures

::: keylet.tkey.Cmd

::: keylet.tkey.Rsp

::: keylet.tkey.LenIdx

## Firmware Commands and Responses

::: keylet.tkey.FwCmd

::: keylet.tkey.FwRsp

## Exceptions

::: keylet.tkey.TKeyError

::: keylet.tkey.TKeyNotFoundError

::: keylet.tkey.TKeyAppError

::: keylet.tkey.TKeyIOError

::: keylet.tkey.TKeyProtocolError
