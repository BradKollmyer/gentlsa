# GenTLSA

CLI for DANE/TLSA records. It prints `TLSA 3 1 1` (DANE-EE, SubjectPublicKeyInfo, SHA-256) from a live TLS certificate or a local PEM/DER file, optionally publishes that record to Cloudflare, and can verify DNS against the certificate the server presents.

Rust port of [Emiel Kollof’s gentlsa](https://github.com/ekollof/gentlsa), with additional features.

Requires a recent stable Rust toolchain (edition 2024) only if you build from source.

## Install

Prebuilt binaries for macOS, Linux, and Windows are published on each [GitHub Release](https://github.com/BradKollmyer/gentlsa/releases).

macOS and Linux:

```
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa-installer.sh | sh
```

Homebrew:

```
brew install BradKollmyer/tap/gentlsa
```

Fedora / RHEL (installs `/usr/bin/gentlsa`):

```
# x86_64
sudo dnf install https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa.x86_64.rpm

# aarch64
sudo dnf install https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa.aarch64.rpm
```

Or download the versioned file (`gentlsa-0.3.4-1.x86_64.rpm`) from the [release page](https://github.com/BradKollmyer/gentlsa/releases) and run `sudo dnf install ./gentlsa-*.rpm`.

Ubuntu / Debian (installs `/usr/bin/gentlsa`):

```
# amd64
curl -fsSL -O https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa.amd64.deb
sudo apt install ./gentlsa.amd64.deb

# arm64
curl -fsSL -O https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa.arm64.deb
sudo apt install ./gentlsa.arm64.deb
```

FreeBSD (installs `/usr/local/bin/gentlsa`):

```
# amd64 (FreeBSD 14+)
sudo pkg add https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa.amd64.pkg
```

Or download the versioned file (`gentlsa-0.3.4.amd64.pkg`) from the [release page](https://github.com/BradKollmyer/gentlsa/releases) and run `sudo pkg add ./gentlsa-*.pkg`. On other major versions, `pkg add -f` if the ABI check refuses the package.

Windows (PowerShell):

```
powershell -ExecutionPolicy Bypass -c "irm https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa-installer.ps1 | iex"
```

From source (this repository):

```
cargo install --path .
```

Or:

```
cargo build --release
./target/release/gentlsa --help
```

`cargo binstall gentlsa` also works once a GitHub Release exists.

## Usage

```
gentlsa [-v|--verbose] [--json] generate <ZONE> <PORTS> [--hostname <HOSTNAME>] [--info] [--cloudflare|--nsupdate|--route53|--google] [--replace] [--dryrun]
gentlsa [-v|--verbose] [--json] list <ZONE> [PORTS] [--hostname <HOSTNAME>] [--cloudflare|--nsupdate|--route53|--google] [--info]
gentlsa [-v|--verbose] [--json] prune <ZONE> <PORTS> [--hostname <HOSTNAME>] [--cloudflare|--nsupdate|--route53|--google] [--dryrun]
gentlsa [-v|--verbose] [--json] verify <ZONE> <PORTS> [--hostname <HOSTNAME>] [--info]
gentlsa [-v|--verbose] [--json] cloudflare [--info] [--listzones]
gentlsa [-v|--verbose] [--json] nsupdate [--info]
gentlsa [-v|--verbose] [--json] route53 [--info] [--listzones]
gentlsa [-v|--verbose] [--json] google [--info] [--listzones]
gentlsa [-v|--verbose] [--json] file <CERTFILE> [--zone <ZONE>] [--hostname <HOSTNAME>] [--port <PORTS>] [--cloudflare|--nsupdate|--route53|--google]
```

`--hostname` is the short host without the zone (`mx` becomes `mx.example.org`). `PORTS` is one port or a comma-separated list (`443` or `25,465`). Ports **25** and **587** use SMTP STARTTLS. Every other port, including 443 and 465, uses implicit TLS. Certificate verification is disabled on purpose so the presented leaf cert can be hashed even when it is expired or otherwise untrusted.

`-v` / `--verbose` prints each processing step to stderr (connect, STARTTLS, handshake, DNS lookup, publisher APIs). Regular output stays on stdout, so `verify` remains Nagios-safe.

`--json` prints one JSON object on stdout instead of text. `--verbose` can still be combined; steps stay on stderr. `verify --json` keeps the same exit codes (`0` / `2` / `3`) and puts the OK/ERROR/UNKNOWN result in `status`, `message`, and `exit`.

```
$ gentlsa generate example.com 443 -v
verbose: generate example.com:443
verbose: connecting to example.com:443 (implicit TLS)
verbose: TCP connected to example.com:443
verbose: TLS handshake with example.com
verbose: received leaf certificate (1234 bytes)
verbose: SPKI SHA-256 0856752f53199a673dcc955c137fe1f5b105a180528acb320bb3eddf15103a9b
_443._tcp TLSA 3 1 1 0856752f53199a673dcc955c137fe1f5b105a180528acb320bb3eddf15103a9b
```

### generate

Fetch the live certificate and print a zone-file style TLSA record:

```
$ gentlsa generate example.com 443
_443._tcp TLSA 3 1 1 0856752f53199a673dcc955c137fe1f5b105a180528acb320bb3eddf15103a9b
```

`--json` wraps the same data:

```
$ gentlsa generate example.com 443 --json
{
  "command": "generate",
  "zone": "example.com",
  "results": [
    {
      "port": 443,
      "host": "example.com",
      "owner": "_443._tcp",
      "usage": 3,
      "selector": 1,
      "matching": 1,
      "certificate": "0856752f53199a673dcc955c137fe1f5b105a180528acb320bb3eddf15103a9b"
    }
  ]
}
```

`--info` adds leaf-certificate details:

```
$ gentlsa generate example.com 443 --info
>>> Certificate Information:
Serial : 624d0ab311558780b7d5213b9631831
Issuer : C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
Subject: CN=example.com
Subject Alternative Name(s): DNS:example.com, DNS:*.example.com
Certificate Inception:  2026-07-29 22:10:08+00:00 UTC
Certificate Expiration: 2026-10-27 22:17:21+00:00 UTC
_443._tcp TLSA 3 1 1 0856752f53199a673dcc955c137fe1f5b105a180528acb320bb3eddf15103a9b
```

SMTP STARTTLS example (connects to `smtp.gmail.com:587`):

```
$ gentlsa generate gmail.com 587 --hostname smtp --info
```

`--cloudflare`, `--nsupdate`, `--route53`, or `--google` publishes the live hash. If a TLSA record already exists, the new hash is **added** and the old one is kept (DANE key rollover). Use `--replace` to overwrite instead. `--dryrun` shows the action without writing. The publishers are mutually exclusive.

```
$ gentlsa generate example.com 443 --cloudflare --info
$ gentlsa generate example.com 25 --hostname mx --cloudflare --dryrun
```

### verify

Compare every TLSA record in DNS at `_<port>._tcp[.<hostname>].<zone>` with the live certificate (Nagios-compatible):

| Exit | Output | Meaning |
|------|--------|---------|
| 0 | `OK - TLSA is valid` | At least one DNS TLSA hash matches the live SPKI SHA-256 |
| 2 | `ERROR - TLSA invalid: ...` | DNS has TLSA records, none match |
| 3 | `UNKNOWN - Something went wrong. Check logs` | Lookup or connection failed |

```
$ gentlsa verify www.freebsd.org 443
OK - TLSA is valid
```

`--info` prints the live certificate before the OK/ERROR/UNKNOWN line.

### list

Show TLSA records from DNS. `--cloudflare`, `--route53`, and `--google` also print what that provider has. `--nsupdate` queries the configured primary (or AXFR when `PORTS` is omitted). `--info` fetches the live certificate and marks each `3 1 1` hash current or stale. Other usage/selector/matching values are listed with their RFC 7218 names and are not compared to the live key. Omit `PORTS` to include every port (Cloudflare, Route 53, Google, and AXFR can list the whole zone; public DNS is queried for each name found there).

```
$ gentlsa list example.com 443
>>> DNS _443._tcp.example.com.
3 1 1 (DANE-EE SPKI SHA2-256) 0856752f53199a673dcc955c137fe1f5b105a180528acb320bb3eddf15103a9b

$ gentlsa list example.com 25,465
$ gentlsa list example.com --cloudflare
$ gentlsa list example.com 443 --cloudflare --info
```

### prune

List (and optionally delete) TLSA records that no longer match the live certificate. Run this after a rollover has been live longer than the DNS TTL.

```
$ gentlsa prune example.com 443 --cloudflare --dryrun
$ gentlsa prune example.com 443 --cloudflare
```

### file

Print the same TLSA data from a local PEM or DER certificate. Certificate details are shown by default. Pass `--port` / `--hostname` to include the owner name. With a publisher flag (and `--zone --port`), publish that file's hash before you reload the service:

```
$ gentlsa file /etc/ssl/certs/example.pem --port 443
>>> Certificate Information:
Serial : ...
Issuer : ...
Subject: ...
Certificate Inception:  ...
Certificate Expiration: ...
_443._tcp TLSA 3 1 1 ...
```

```
$ gentlsa file /etc/letsencrypt/live/example.com/cert.pem --zone example.com --port 443 --cloudflare
```

## Certificate renewal / key rollover

`TLSA 3 1 1` hashes the leaf public key. A typical Let's Encrypt renewal mints a new key, so the hash changes. Replacing the DNS record at the same moment you reload the cert leaves a window where caches have one side of the pair and not the other.

Safer sequence:

1. Issue the new certificate, but do not reload the service yet.
2. Publish the **new** hash next to the old one:
   ```
   gentlsa file /etc/letsencrypt/live/example.com/cert.pem --zone example.com --port 443 --cloudflare
   # or: --nsupdate / --route53 / --google
   ```
3. Wait at least as long as the TLSA TTL (and any resolver cache).
4. Reload the service so it presents the new certificate.
5. After another TTL, drop the old hash:
   ```
   gentlsa prune example.com 443 --cloudflare
   ```

If the new cert is already live, `generate --cloudflare` still **adds** the live hash instead of overwriting. That does not fix clients that only cached the old record, but it avoids deleting a hash that some resolvers still expect.

`--replace` restores the old one-record overwrite.

### cloudflare

```
$ gentlsa cloudflare --listzones
>>> Cloudflare Zones:
<zone-id>  example.com

$ gentlsa cloudflare --info
>>> Cloudflare Information:
Auth: API token
```

`--listzones` is implied when `--info` is omitted.

## Cloudflare credentials

Create `/etc/gentlsa/cloudflare.cfg`. A scoped API token (no email) is preferred:

```
[CloudFlare]
token = <api token>
```

`api_token` is accepted as an alias for `token`. A global API key still works if both email and token are set:

```
[CloudFlare]
email = <cloudflare login>
token = <global API key>
```

`~/.cloudflare/cloudflare.cfg` is still read if `/etc/gentlsa/cloudflare.cfg` is missing.

Environment variables override the config file:

| Variable | Use |
|----------|-----|
| `CF_API_TOKEN` or `CLOUDFLARE_API_TOKEN` | Bearer API token |
| `CF_API_EMAIL` + `CF_API_KEY` | Global API key |
| `CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY` | Same as above |

The token needs Zone read and DNS edit on the zones you publish to.

## nsupdate (RFC 2136 / TSIG)

`--nsupdate` talks to an authoritative nameserver with RFC 2136 dynamic updates, signed with TSIG. This is the self-hosted counterpart to `--cloudflare`. It does not shell out to the BIND `nsupdate` binary.

Create `/etc/gentlsa/nsupdate.cfg` (or `~/.gentlsa/nsupdate.cfg`):

```
[Nsupdate]
server = ns1.example.com
port = 53
key-name = gentlsa-update.
secret = <base64 hmac>
algorithm = hmac-sha256
ttl = 3600
```

`hmac-sha256` is the default and the recommended algorithm. `hmac-sha384` and `hmac-sha512` are also accepted. The secret is BIND-style base64 (hex is accepted too).

Environment variables override the config file:

| Variable | Use |
|----------|-----|
| `GENTLSA_NSUPDATE_SERVER` | Nameserver host |
| `GENTLSA_NSUPDATE_PORT` | Nameserver port (default 53) |
| `GENTLSA_NSUPDATE_KEY_NAME` | TSIG key name |
| `GENTLSA_NSUPDATE_SECRET` | TSIG secret |
| `GENTLSA_NSUPDATE_ALGORITHM` | `hmac-sha256` / `hmac-sha384` / `hmac-sha512` |
| `GENTLSA_NSUPDATE_TTL` | TTL for new records (default 3600) |

```
$ gentlsa nsupdate --info
>>> nsupdate Information:
Server: ns1.example.com:53
Key name: gentlsa-update.
Algorithm: hmac-sha256
TTL: 3600

$ gentlsa generate example.com 443 --nsupdate --dryrun
$ gentlsa file /etc/letsencrypt/live/example.com/cert.pem --zone example.com --port 443 --nsupdate
$ gentlsa list example.com 443 --nsupdate --info
$ gentlsa prune example.com 443 --nsupdate --dryrun
```

`list --nsupdate` without ports tries AXFR. If the key is not allowed to transfer the zone, pass the ports instead.

The nameserver must allow UPDATE (and AXFR, if you want port-less `list`) for that TSIG key on the zone.

## Route 53

`--route53` publishes TLSA through the Amazon Route 53 REST API (SigV4). Create `/etc/gentlsa/route53.cfg` (or `~/.gentlsa/route53.cfg`):

```
[Route53]
access_key = AKIA...
secret_key = ...
ttl = 3600
```

`session_token` is accepted for temporary credentials. Environment variables override the config file:

| Variable | Use |
|----------|-----|
| `AWS_ACCESS_KEY_ID` or `GENTLSA_AWS_ACCESS_KEY_ID` | Access key |
| `AWS_SECRET_ACCESS_KEY` or `GENTLSA_AWS_SECRET_ACCESS_KEY` | Secret key |
| `AWS_SESSION_TOKEN` or `GENTLSA_AWS_SESSION_TOKEN` | Session token (optional) |

The IAM principal needs `route53:ListHostedZones`, `route53:ListResourceRecordSets`, and `route53:ChangeResourceRecordSets` on the hosted zones you publish to.

```
$ gentlsa route53 --listzones
$ gentlsa route53 --info
$ gentlsa generate example.com 443 --route53 --dryrun
$ gentlsa list example.com 443 --route53 --info
$ gentlsa prune example.com 443 --route53 --dryrun
```

## Google Cloud DNS

`--google` publishes TLSA through the Cloud DNS REST API. Point `GOOGLE_APPLICATION_CREDENTIALS` at a service-account JSON key, or create `/etc/gentlsa/google.cfg` (or `~/.gentlsa/google.cfg`):

```
[Google]
credentials = /etc/gentlsa/google-sa.json
project = my-gcp-project
ttl = 3600
```

The project can also come from `project_id` in the service-account JSON.

| Variable | Use |
|----------|-----|
| `GOOGLE_APPLICATION_CREDENTIALS` or `GENTLSA_GOOGLE_CREDENTIALS` | Path to service-account JSON |
| `GENTLSA_GOOGLE_PROJECT`, `GOOGLE_CLOUD_PROJECT`, or `GCLOUD_PROJECT` | GCP project |

The service account needs `dns.managedZones.list`, `dns.resourceRecordSets.list`, and `dns.changes.create` (DNS Administrator, or a custom role with those permissions).

```
$ gentlsa google --listzones
$ gentlsa google --info
$ gentlsa generate example.com 443 --google --dryrun
$ gentlsa list example.com 443 --google --info
$ gentlsa prune example.com 443 --google --dryrun
```

DigitalOcean DNS is not supported: the official API has no TLSA record type and no DNSSEC.

## Development

```
cargo test
cargo clippy --all-targets -- -D warnings
```

CI runs `cargo test --release` and a binary smoke test (`scripts/smoke-test.sh`) on Linux (x86_64 and arm64), macOS (Apple Silicon and Intel), Windows (x86_64 and arm64), and FreeBSD 14 amd64. The FreeBSD job also `pkg add`s the built `.pkg` and re-runs the smoke test on `/usr/local/bin/gentlsa`.

To build local RPM and deb packages (`cargo-generate-rpm` and `cargo-deb` required):

```
./scripts/build-rpms.sh
```

To build a local FreeBSD `.pkg` (amd64). On macOS this cross-compiles inside an [Apple container](https://github.com/apple/container) (not Docker):

```
./scripts/build-pkg.sh
```

Fixture certificate used by the hash tests: `tests/fixtures/test.example.pem`.

Releases are cut by bumping `version` in `Cargo.toml` and pushing a matching tag. [dist](https://github.com/axodotdev/cargo-dist) then builds binaries and installers and publishes the Homebrew formula to [BradKollmyer/homebrew-tap](https://github.com/BradKollmyer/homebrew-tap):

```
# bump version in Cargo.toml and CHANGELOG.md
git commit -am "release: 0.3.4"
git tag v0.3.4
git push && git push --tags
```

## License

BSD-2-Clause. Copyright (c) 2018 Emiel Kollof; Copyright (c) 2026 Brad Kollmyer. See [LICENSE](LICENSE).
