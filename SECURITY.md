# Security policy

## Reporting a vulnerability

Report vulnerabilities privately via GitHub's
[private advisory form](https://github.com/BradKollmyer/gentlsa/security/advisories/new).

Do not open a public issue for security reports.

## Scope

gentlsa is a DANE/TLSA CLI that talks to DNS providers and handles TLS
certificates. Reports are especially welcome for:

- Secret leakage (API tokens, TSIG keys, cloud credentials)
- TLS verification bypass
- Incorrect TLSA generation or DNS publishing
- Command injection around subprocesses such as `nsupdate`

## Supported versions

The latest GitHub release is supported.
