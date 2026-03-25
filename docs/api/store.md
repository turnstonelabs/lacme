# Store

Certificate and account key storage. Provides a `Store` protocol and two built-in
implementations: `FileStore` for filesystem persistence and `MemoryStore` for testing.

## Store Protocol

::: lacme.store.Store
    options:
      show_bases: true
      members:
        - save_account_key
        - load_account_key
        - save_cert
        - load_cert
        - list_certs
        - save_ca
        - load_ca

## FileStore

::: lacme.store.FileStore
    options:
      show_bases: true
      members:
        - __init__
        - base
        - save_account_key
        - load_account_key
        - save_cert
        - load_cert
        - list_certs
        - save_ca
        - load_ca

## MemoryStore

::: lacme.store.MemoryStore
    options:
      show_bases: true
      members:
        - __init__
        - save_account_key
        - load_account_key
        - save_cert
        - load_cert
        - list_certs
        - save_ca
        - load_ca
