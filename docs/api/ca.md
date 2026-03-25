# Certificate Authority

Lightweight Certificate Authority for internal PKI and mTLS use. Generates a
self-signed root CA and signs server or client certificates.

::: lacme.ca.CertificateAuthority
    options:
      show_bases: true
      members:
        - __init__
        - init
        - issue
        - issue_from_csr
        - root_cert_pem
        - initialized
