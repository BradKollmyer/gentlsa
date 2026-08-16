# Changelog

## 0.3.0 - 2026-08-16

- Rewrite gentlsa as a Rust CLI (`generate`, `verify`, `file`, `cloudflare`)
- Generate `TLSA 3 1 1` records from live TLS, SMTP STARTTLS, or a local PEM/DER file
- Verify DNS TLSA against the live certificate (Nagios-compatible exit codes)
- Publish or update Cloudflare TLSA records
- Ship multi-platform binaries and installers with dist (shell, PowerShell, Homebrew)

## 0.2.0 - 2026-08-16

- Initial Rust port of the Python tool
