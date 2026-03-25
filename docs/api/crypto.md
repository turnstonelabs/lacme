# Crypto

Pure cryptographic functions for ACME operations: base64url encoding, EC P-256 key
generation, JWK/JWS construction, CSR generation, and key authorization computation.

## Key Generation

::: lacme.crypto.generate_ec_key
    options:
      show_root_heading: true

## PEM Serialization

::: lacme.crypto.private_key_to_pem
    options:
      show_root_heading: true

::: lacme.crypto.private_key_from_pem
    options:
      show_root_heading: true

## JWK

::: lacme.crypto.public_key_to_jwk
    options:
      show_root_heading: true

::: lacme.crypto.jwk_thumbprint
    options:
      show_root_heading: true

::: lacme.crypto.account_thumbprint
    options:
      show_root_heading: true

## Key Authorization

::: lacme.crypto.key_authorization
    options:
      show_root_heading: true

## CSR Generation

::: lacme.crypto.generate_csr
    options:
      show_root_heading: true

## Base64url

::: lacme.crypto.b64url_encode
    options:
      show_root_heading: true

::: lacme.crypto.b64url_decode
    options:
      show_root_heading: true

## JWS

::: lacme.crypto.jws_encode
    options:
      show_root_heading: true

::: lacme.crypto.jws_encode_hmac
    options:
      show_root_heading: true

## Certificate Conversion

::: lacme.crypto.pem_to_der_certificate
    options:
      show_root_heading: true
