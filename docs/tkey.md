# Low-Level TKey Protocol

This page documents the lower-level protocol, framing classes, and exception hierarchy of the `keylet` library. These are useful if you want to implement custom host applications or interact with the TKey firmware directly.

## Base TKey Client

::: keylet.tkey.TKey

## Protocol Structures

::: keylet.tkey.Cmd

::: keylet.tkey.Rsp

::: keylet.tkey.LenIdx

## Firmware Commands and Responses

::: keylet.tkey.FwCmd

::: keylet.tkey.FwRsp

## Exceptions

::: keylet.tkey
    options:
      filters:
        - "^TKey.*Error$"
      show_root_heading: false
      show_category_heading: false
