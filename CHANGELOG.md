# Changelog

## Unreleased

- Add `--json` to emit a single JSON object on stdout
- Add `-v` / `--verbose` to print each processing step on stderr
- Accept a comma-separated port list (`25,465`) on generate, list, prune, verify, and file
- `list` with no ports shows records for every port
- CI: `cargo test --release` and a binary smoke test on Linux, macOS, Windows (x86_64 and arm64), and FreeBSD 14 amd64

## 0.3.4 - 2026-08-16

- Ship FreeBSD `.pkg` packages (`pkg add`) for amd64
- Add `list` and `prune` for inspecting and dropping stale TLSA records
- Cloudflare publish adds a rollover hash instead of overwriting; `--replace` restores overwrite
- `file --cloudflare` can publish a not-yet-live certificate

## 0.3.3 - 2026-08-16

- Fix RPM architecture so `gentlsa.x86_64.rpm` is actually x86_64, not aarch64

## 0.3.2 - 2026-08-16

- Ship Ubuntu/Debian `.deb` packages (`apt install`) for amd64 and arm64

## 0.3.1 - 2026-08-16

- Ship Fedora/RHEL RPMs (`dnf install`) for x86_64 and aarch64

## 0.3.0 - 2026-08-16

- Rewrite gentlsa as a Rust CLI (`generate`, `verify`, `file`, `cloudflare`)
- Generate `TLSA 3 1 1` records from live TLS, SMTP STARTTLS, or a local PEM/DER file
- Verify DNS TLSA against the live certificate (Nagios-compatible exit codes)
- Publish or update Cloudflare TLSA records
- Ship multi-platform binaries and installers with dist (shell, PowerShell, Homebrew)

## 0.2.0 - 2026-08-16

- Initial Rust port of the Python tool
