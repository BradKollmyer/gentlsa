# Changelog

## Unreleased

- `--mx` DNSSEC-validates the MX RRset itself, not just the TLSA records (RFC 7672 §2.2). A forged insecure MX answer lets an attacker choose the host and then publish a properly signed TLSA for a key they hold, so `verify --mx` reports an unauthenticated MX RRset as WARNING and a bogus one as CRITICAL even when the TLSA records validate; `generate --mx` and `prune --mx` warn on stderr. `--no-dnssec-check` skips it, and `verify --json` reports the verdict in `mx_dnssec`
- `--mx` on `generate`, `verify`, and `prune` looks up the zone's MX RRset and operates on each exchange host (lowest preference first), so DANE-for-mail does not need a `--hostname` per MX. Out-of-zone exchanges are checked but cannot be published into the zone. Null MX (RFC 7505) is skipped
- `--timeout <SECONDS>` (default 30) is an overall deadline for connect, socket I/O, and DNS, so Nagios `verify` can finish before the service check timeout. TCP connect was previously unbounded
- `--starttls smtp|imap|pop3|xmpp|none` selects the plaintext upgrade independently of the port on `generate`, `verify`, `list`, `prune`, and `rollover`. When omitted, 25/587 are SMTP, 143 IMAP, 110 POP3, and 5222/5269 XMPP; every other port stays implicit TLS. `--starttls none` forces implicit TLS on a STARTTLS port
- `gentlsa completions <shell>` prints a bash, zsh, fish, PowerShell, or elvish completion script; the RPM, deb, and FreeBSD packages install the bash, zsh, and fish ones
- `generate` and `file` accept `--usage`, `--selector`, and `--matching` to emit TLSA parameters other than 3 1 1 (DANE-TA 2 1 1, full-cert selector 0, SHA2-512, exact matching); with usage 0/2, `generate` hashes the first issuer certificate the server presents. Publishing stays 3 1 1-only and other parameters are rejected with a clear error
- `verify` evaluates every DNS TLSA record with its own parameters against the presented chain (usage 1/3 against the leaf, 0/2 against any presented certificate, selectors 0/1, matching 0/1/2), so zones publishing only DANE-TA `2 1 1` no longer report a false ERROR
- `verify` validates the TLSA records with DNSSEC (locally, from the root trust anchor): an unauthenticated RRset is WARNING — DANE clients ignore TLSA records they cannot authenticate — and a bogus RRset is CRITICAL; `--no-dnssec-check` restores the pre-0.5.0 behavior, and `--json` reports the verdict in `dnssec`
- Publishing to a zone with no DS record warns on stderr that DANE clients will ignore its TLSA records
- Ship `gentlsa(1)` and `gentlsa(5)` man pages in the RPM, deb, and FreeBSD packages
- Publish, list, and prune TLSA records via Azure DNS (`--azure`)

## 0.4.3 - 2026-08-17

- `rollover` waits 2× the TLSA TTL before reload and again before prune (RFC 7671 §8.1)

## 0.4.2 - 2026-08-17

- `verify --no-expiry-check` restores the hash-only verdict (the pre-0.4.1 exit behavior, where a matching cert near expiry still exits 0)
- `verify` rejects `--critical` greater than `--warn` with exit 3 (UNKNOWN) instead of 1, and still emits a JSON object with `--json`
- `verify --json` reports expiry-driven CRITICAL results as `"status": "critical"` (previously `"error"`, indistinguishable from a TLSA mismatch)
- `verify` with a port list picks the overall exit by Nagios severity (CRITICAL > WARNING > UNKNOWN > OK) instead of the numeric maximum, so an UNKNOWN no longer hides a CRITICAL

## 0.4.1 - 2026-08-17

- `verify` warns (exit 1) or goes critical (exit 2) when the live certificate is near expiry (`--warn` / `--critical`, default 14 / 7 days)

## 0.4.0 - 2026-08-17

- `rollover` publishes a not-yet-live certificate hash, waits the TLSA TTL, reloads, waits again, then prunes
- Persist in-progress rollovers and resume them after a reboot (`--resume`, `--schedule`)
- Ship `gentlsa-resume.service` / `.timer` and `gentlsa-rollover@.service` in the RPM and deb packages (not the FreeBSD `.pkg`)

## 0.3.5 - 2026-08-17

- `list` (and prune DNS lines) decode TLSA usage/selector/matching with RFC 7218 names
- Publish, list, and prune TLSA records via RFC 2136 dynamic update (`--nsupdate`, TSIG)
- Publish, list, and prune TLSA records via Amazon Route 53 (`--route53`)
- Publish, list, and prune TLSA records via Google Cloud DNS (`--google`)
- Read Cloudflare credentials from `/etc/gentlsa/cloudflare.cfg` (falls back to `~/.cloudflare/cloudflare.cfg`)
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
