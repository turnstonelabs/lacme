# Challenges

ACME challenge handlers for HTTP-01 and DNS-01 validation, including the
`ChallengeHandler` protocol and pluggable DNS providers (Cloudflare, Route 53, Hook).

## ChallengeHandler Protocol

::: lacme.challenges.ChallengeHandler
    options:
      show_bases: true
      members:
        - provision
        - deprovision

## HTTP-01

::: lacme.challenges.http01.HTTP01Handler
    options:
      show_bases: true
      members:
        - __init__
        - provision
        - deprovision
        - get_response
        - start_server

## DNS-01

::: lacme.challenges.dns01.DNS01Handler
    options:
      show_bases: true
      members:
        - __init__
        - provision
        - deprovision

## DNSProvider Protocol

::: lacme.challenges.dns01.DNSProvider
    options:
      show_bases: true
      members:
        - create_txt_record
        - delete_txt_record

## DNS Providers

### CloudflareDNSProvider

::: lacme.challenges.providers.cloudflare.CloudflareDNSProvider
    options:
      show_bases: true
      members:
        - __init__
        - create_txt_record
        - delete_txt_record
        - close

### Route53DNSProvider

::: lacme.challenges.providers.route53.Route53DNSProvider
    options:
      show_bases: true
      members:
        - __init__
        - create_txt_record
        - delete_txt_record

### HookDNSProvider

::: lacme.challenges.providers.hook.HookDNSProvider
    options:
      show_bases: true
      members:
        - __init__
        - create_txt_record
        - delete_txt_record
