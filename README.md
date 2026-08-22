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

Fedora / RHEL (installs `/usr/bin/gentlsa`, man pages, and the systemd units):

```
# x86_64
sudo dnf install https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa.x86_64.rpm

# aarch64
sudo dnf install https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa.aarch64.rpm
```

Or download the versioned file (`gentlsa-0.5.1-1.x86_64.rpm`) from the [release page](https://github.com/BradKollmyer/gentlsa/releases) and run `sudo dnf install ./gentlsa-*.rpm`. Same files if you `rpm -i` the package. After install, enable the resume timer if you use `rollover`:

```
sudo systemctl enable --now gentlsa-resume.timer
```

Ubuntu / Debian (installs `/usr/bin/gentlsa`, man pages, and the same systemd units):

```
# amd64
curl -fsSL -O https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa.amd64.deb
sudo apt install ./gentlsa.amd64.deb

# arm64
curl -fsSL -O https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa.arm64.deb
sudo apt install ./gentlsa.arm64.deb
```

Then `sudo systemctl enable --now gentlsa-resume.timer` if you use `rollover`.

FreeBSD (installs `/usr/local/bin/gentlsa` and man pages — no systemd units):

```
# amd64 (FreeBSD 14+)
sudo pkg add https://github.com/BradKollmyer/gentlsa/releases/latest/download/gentlsa.amd64.pkg
```

Or download the versioned file (`gentlsa-0.5.1.amd64.pkg`) from the [release page](https://github.com/BradKollmyer/gentlsa/releases) and run `sudo pkg add ./gentlsa-*.pkg`. On other major versions, `pkg add -f` if the ABI check refuses the package. Resume an interrupted rollover with `gentlsa rollover --resume` from cron or `@reboot`.

The RPM, deb, and FreeBSD packages install `gentlsa(1)` and `gentlsa(5)` (`man gentlsa`).

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
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] generate <ZONE> <PORTS> [--hostname <HOSTNAME>|--mx] [--starttls smtp|imap|pop3|xmpp|none] [--info] [--usage <N>] [--selector <N>] [--matching <N>] [--cloudflare|--nsupdate|--route53|--google|--azure] [--replace] [--dryrun]
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] list <ZONE> [PORTS] [--hostname <HOSTNAME>] [--starttls smtp|imap|pop3|xmpp|none] [--cloudflare|--nsupdate|--route53|--google|--azure] [--info]
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] prune <ZONE> <PORTS> [--hostname <HOSTNAME>|--mx] [--starttls smtp|imap|pop3|xmpp|none] [--cloudflare|--nsupdate|--route53|--google|--azure] [--dryrun]
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] rollover <CERTFILE> <ZONE> <PORTS> [--hostname <HOSTNAME>] [--starttls smtp|imap|pop3|xmpp|none] [--cloudflare|--nsupdate|--route53|--google|--azure] [--reload <CMD>] [--ttl <SECONDS>] [--schedule] [--dryrun]
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] rollover --resume [JOB]
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] verify <ZONE> <PORTS> [--hostname <HOSTNAME>|--mx] [--starttls smtp|imap|pop3|xmpp|none] [--info] [--warn <DAYS>] [--critical <DAYS>] [--no-expiry-check] [--no-dnssec-check]
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] cloudflare [--info] [--listzones]
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] nsupdate [--info]
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] route53 [--info] [--listzones]
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] google [--info] [--listzones]
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] azure [--info] [--listzones]
gentlsa completions <bash|zsh|fish|powershell|elvish>
gentlsa [-v|--verbose] [--json] [--timeout <SECONDS>] file <CERTFILE> [--zone <ZONE>] [--hostname <HOSTNAME>] [--port <PORTS>] [--usage <N>] [--selector <N>] [--matching <N>] [--cloudflare|--nsupdate|--route53|--google|--azure]
```

`--hostname` is the short host without the zone (`mx` becomes `mx.example.org`). `PORTS` is one port or a comma-separated list (`443` or `25,465`). `--starttls smtp|imap|pop3|xmpp|none` selects the plaintext upgrade before TLS. When omitted, ports **25** and **587** use SMTP, **143** IMAP, **110** POP3, and **5222**/**5269** XMPP. Every other port, including 443, 465, 993, and 995, uses implicit TLS. `--starttls none` forces implicit TLS on a STARTTLS port; `--starttls smtp` (or `imap`/`pop3`/`xmpp`) forces that protocol on a nonstandard port. Certificate verification is disabled on purpose so the presented leaf cert can be hashed even when it is expired or otherwise untrusted.

For XMPP, the stream's `to=` attribute and the TLS SNI are the **zone**, not the host connected to: RFC 6120 §4.7.2 requires the XMPP domain there, and RFC 7673 §6 expects the certificate to match that same domain. So `gentlsa generate example.com 5222 --hostname xmpp` connects to `xmpp.example.com`, opens the stream to `example.com`, and publishes the TLSA at `_5222._tcp.xmpp.example.com` — which is where a DANE-SRV client looks. Sending the SRV target instead makes servers that only service the domain answer `<host-unknown/>` and close the connection.

SMTP `EHLO` sends the connection's own source address as an RFC 5321 §4.1.3 address literal (`EHLO [192.0.2.10]`), which is what the RFC asks for when the client has no resolvable name. Behind NAT this is the private address; that is still valid syntax and is accepted by hardened servers such as Postfix with `reject_non_fqdn_helo_hostname`.

`-v` / `--verbose` prints each processing step to stderr (connect, STARTTLS, handshake, DNS lookup, publisher APIs). Regular output stays on stdout, so `verify` remains Nagios-safe.

`--json` prints one JSON object on stdout instead of text. `--verbose` can still be combined; steps stay on stderr. `verify --json` keeps the same exit codes (`0` / `1` / `2` / `3`) and puts the result in `status` (`ok` / `warning` / `critical` / `error` / `unknown`), `message`, and `exit`.

`--timeout <SECONDS>` (default 30) is a deadline for hostname resolution, TCP connect, STARTTLS, the TLS handshake, and DNS (including DNSSEC). A timed-out `verify` exits UNKNOWN. Set this below the Nagios service check timeout (for example `--timeout 10` when the check is 15s).

It is a real deadline, not a per-operation one: every socket read and write is re-armed to what is left of the budget, so a peer that trickles bytes just under the limit cannot stretch the run out. It bounds network work, not the lifetime of the process: `rollover` deliberately sleeps two TLSA TTLs between phases and shells out to `--reload`, so the budget is re-armed after each wait and after the reload command. Otherwise the prune phase would open its connection with a deadline that expired hours earlier.

`--mx` looks up the zone's MX records and runs the command on each exchange host (lowest preference first). Conflicts with `--hostname`. Port 25 is the usual DANE SMTP port. An MX that lives in another zone is still verified or printed; publishing its TLSA into this zone is refused. A null MX (RFC 7505) is skipped.

An exchange that cannot be reached does not abort the run: the failure is recorded (in `--json`, as `error` on that result, with `certificate` omitted) and the remaining hosts are still processed. The command then exits non-zero even if a later host succeeded. The same applies to a port list.

The MX RRset is itself DNSSEC-validated. SMTP DANE only means something over a secure MX RRset (RFC 7672 §2.2): whoever can forge an insecure MX answer picks the hostname you connect to, and can then publish a properly signed TLSA record at that name for a key they hold — every per-host check would report `secure` while the attacker chose the host. So `verify --mx` treats an unauthenticated MX RRset as WARNING and a bogus one as CRITICAL, even when the TLSA records themselves validate; `--no-dnssec-check` skips both checks. `generate --mx` and `prune --mx` print a warning on stderr instead.

```
$ gentlsa verify example.com 25 --mx
mail.example.com: OK - TLSA is valid
backup.example.net: OK - TLSA is valid
```

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

IMAP on the well-known port, or SMTP on a nonstandard port:

```
$ gentlsa generate example.com 143 --hostname imap
$ gentlsa generate example.com 2525 --hostname mx --starttls smtp
$ gentlsa generate example.com 25 --starttls none
```

`--usage` (0-3, default 3 DANE-EE), `--selector` (0 full certificate, 1 SubjectPublicKeyInfo; default 1), and `--matching` (0 exact, 1 SHA2-256, 2 SHA2-512; default 1) select other TLSA parameters. With usage 0 or 2 (trust anchor), `generate` hashes the first issuer certificate the server presents instead of the leaf (a self-signed leaf is its own anchor):

```
$ gentlsa generate example.com 443 --usage 2
_443._tcp TLSA 2 1 1 e38be21734c2fa1fcbfb7387460e11b39bf8f80729cc766f23d4e77b64433469
```

`--cloudflare`, `--nsupdate`, `--route53`, `--google`, or `--azure` publishes the live hash. If a TLSA record already exists, the new hash is **added** and the old one is kept (DANE key rollover). Use `--replace` to overwrite instead. `--dryrun` shows the action without writing. The publishers are mutually exclusive. Publishing to a zone that has no DS record prints a warning on stderr: without a signed delegation, DANE clients cannot authenticate the TLSA records and ignore them. Publishing is limited to `3 1 1` records; other `--usage`/`--selector`/`--matching` values are print-only for now.

```
$ gentlsa generate example.com 443 --cloudflare --info
$ gentlsa generate example.com 25 --hostname mx --cloudflare --dryrun
```

### verify

Compare every TLSA record in DNS at `_<port>._tcp[.<hostname>].<zone>` with the live certificate chain (Nagios-compatible). Each record is evaluated with its own parameters: usage 1/3 against the leaf, usage 0/2 against every certificate the server presents, selectors 0/1, matching types 0/1/2 (hash presence only — no PKIX or DANE-TA chain validation). A zone that publishes only `2 1 1` therefore verifies correctly. After a hash match, remaining days until `notAfter` are checked against `--warn` (default 14) and `--critical` (default 7). `--critical` cannot be greater than `--warn` (rejected with exit 3, UNKNOWN). `--no-expiry-check` skips the expiry check and restores the hash-only verdict (the pre-0.4.1 exit behavior). A hash mismatch stays `ERROR` even if the cert is also expiring.

The TLSA records are also validated with DNSSEC (locally, from the root trust anchor, through the system resolver). A DANE client only honors TLSA records that validate as secure, so a matching hash in an unsigned zone is `WARNING` — DANE is inert there — and a bogus RRset is `CRITICAL`, because validating resolvers answer SERVFAIL and DANE clients cannot connect at all. `--no-dnssec-check` skips this (the pre-0.5.0 behavior). Note that a resolver that strips DNSSEC records (some home routers) makes every zone look unauthenticated; point `/etc/resolv.conf` at a full resolver or use `--no-dnssec-check`.

| Exit | Output | Meaning |
|------|--------|---------|
| 0 | `OK - TLSA is valid` | At least one DNS TLSA hash matches, and the cert expires after `--warn` days |
| 1 | `WARNING - certificate expires in N days` | Hash matches, days left ≤ `--warn` |
| 1 | `WARNING - TLSA records are not DNSSEC-authenticated (insecure)` | Hash matches, but the zone is not DNSSEC-signed, so DANE clients ignore the records |
| 1 | `WARNING - MX records are not DNSSEC-authenticated (insecure)` | `--mx` only: the TLSA records check out, but the MX RRset that chose the host is unsigned |
| 2 | `CRITICAL - certificate expires in N days` | Hash matches, days left ≤ `--critical` (`expires in 1 day` / `expires today` near zero) |
| 2 | `CRITICAL - certificate expired` | Hash matches, `notAfter` has passed |
| 2 | `CRITICAL - certificate is not yet valid` | Hash matches, `notBefore` has not been reached |
| 2 | `CRITICAL - TLSA records failed DNSSEC validation (bogus)` | The TLSA RRset does not validate; validating resolvers SERVFAIL on it |
| 2 | `CRITICAL - MX records failed DNSSEC validation (bogus)` | `--mx` only: the MX RRset does not validate |
| 2 | `ERROR - TLSA invalid: ...` | DNS has TLSA records, none match |
| 3 | `UNKNOWN - Something went wrong. Check logs` | Lookup or connection failed |

With a port list, the overall exit is the worst result by Nagios severity: CRITICAL > WARNING > UNKNOWN > OK, so a transient lookup failure on one port cannot hide a CRITICAL on another.

```
$ gentlsa verify www.freebsd.org 443
OK - TLSA is valid
```

`--info` prints the live certificate before the OK/WARNING/CRITICAL/ERROR/UNKNOWN line. In JSON, each result's `status` is `ok`, `warning`, `critical` (expiry or bogus DNSSEC), `error` (TLSA mismatch), or `unknown`, `expires_in_days` is included when the result was computed from a fetched live certificate (it is omitted on failed lookups, connections, and parses), `mx_dnssec` is the MX RRset's verdict under `--mx`, and `dnssec` is the TLSA validation verdict (`secure`, `insecure`, `bogus`, or `indeterminate`; omitted with `--no-dnssec-check` and on failed lookups).

### list

Show TLSA records from DNS. `--cloudflare`, `--route53`, `--google`, and `--azure` also print what that provider has. `--nsupdate` queries the configured primary (or AXFR when `PORTS` is omitted). `--info` fetches the live certificate and marks each `3 1 1` hash current or stale. Other usage/selector/matching values are listed with their RFC 7218 names and are not compared to the live key. Omit `PORTS` to include every port (Cloudflare, Route 53, Google, Azure, and AXFR can list the whole zone; public DNS is queried for each name found there).

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

### rollover

Publish a not-yet-live certificate hash, wait two TLSA TTLs (RFC 7671), run `--reload`, wait two TTLs again, then prune hashes that no longer match the live certificate. A publisher flag is required. `--replace` is not available.

```
$ gentlsa rollover /etc/letsencrypt/live/example.com/cert.pem example.com 443 \
    --cloudflare --reload "systemctl reload nginx"
```

`--ttl` is the TLSA record TTL: 300s for Cloudflare (auto TTL) and 3600s for `--nsupdate`, `--route53`, `--google`, and `--azure`. Each wait is **2×** that value (600s / 7200s). `--ttl 0` skips both waits (unsafe on a live resolver). `--dryrun` prints the sequence without writing, sleeping, or running `--reload`.

Without `--reload`, only the new hash is published and the remaining wait / reload / prune steps are printed. Do not prune before the service presents the new cert.

With `--reload`, a job is written under `/var/lib/gentlsa/rollover/` (or `$GENTLSA_STATE_DIR`, else `~/.local/share/gentlsa/rollover`). `gentlsa rollover --resume` continues from the saved deadlines. `--resume example.com` (or `example.com_443`) limits that to one job.

`--schedule` writes the job and starts `gentlsa-rollover@JOB` so the hook does not block:

```
$ gentlsa rollover /etc/letsencrypt/live/example.com/cert.pem example.com 443 \
    --cloudflare --reload "systemctl reload nginx" --schedule
```

See [Certificate renewal / key rollover](#certificate-renewal--key-rollover) for the DANE sequence, certbot, and which packages ship the systemd units.

### file

Print the same TLSA data from a local PEM or DER certificate. Certificate details are shown by default. `--usage`/`--selector`/`--matching` work as in `generate`; for a trust-anchor record (`--usage 2`), pass the CA certificate file itself. Pass `--port` / `--hostname` to include the owner name. With a publisher flag (and `--zone --port`), publish that file's hash before you reload the service:

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

### completions

Print a shell completion script on stdout:

```
$ gentlsa completions bash
$ gentlsa completions zsh
$ gentlsa completions fish
```

`powershell` and `elvish` also work. The RPM, deb, and FreeBSD packages install the bash, zsh, and fish scripts already — nothing to do there. For Homebrew, `cargo install`, or the curl/PowerShell installer, install one yourself:

```
# bash
gentlsa completions bash | sudo tee /usr/share/bash-completion/completions/gentlsa >/dev/null

# zsh (a directory on your $fpath)
gentlsa completions zsh | sudo tee /usr/local/share/zsh/site-functions/_gentlsa >/dev/null

# fish
gentlsa completions fish > ~/.config/fish/completions/gentlsa.fish
```

The generated scripts are also checked in under `contrib/completions/`.

## Certificate renewal / key rollover

`TLSA 3 1 1` hashes the leaf public key. A typical Let's Encrypt renewal mints a new key, so the hash changes. Replacing the DNS record at the same moment you reload the cert leaves a window where caches have one side of the pair and not the other.

[`rollover`](#rollover) is the automated sequence: publish the file hash (not yet served), wait two TTLs, `--reload`, wait two TTLs again, prune. After a reboot the new cert is usually already live (the service re-reads the PEM); `--resume` notices that, skips `--reload`, and only waits until it is safe to prune.

### systemd units

| Package | Units? |
|---------|--------|
| Fedora / RHEL (`dnf` / `rpm`) | Yes |
| Ubuntu / Debian (`apt` / `.deb`) | Yes |
| FreeBSD (`pkg`) | No |
| Homebrew, `cargo install`, curl/PowerShell installer | No |

The Linux RPM and deb install:

| Path | Role |
|------|------|
| `/usr/lib/systemd/system/gentlsa-resume.service` | `gentlsa rollover --resume` (every pending job) |
| `/usr/lib/systemd/system/gentlsa-resume.timer` | 1 minute after boot, then every 10 minutes |
| `/usr/lib/systemd/system/gentlsa-rollover@.service` | Resume one job (`example.com_443`) |
| `/usr/lib/tmpfiles.d/gentlsa.conf` | Creates `/var/lib/gentlsa/rollover` |

Install does **not** enable the timer. After `dnf install` or `apt install`:

```
sudo systemctl enable --now gentlsa-resume.timer
```

`--schedule` writes the job and starts `gentlsa-rollover@example.com_443.service`. If systemd is missing, it prints the `systemctl start` line and leaves the job for `--resume`.

Homebrew and the curl installer do not ship units. Copy `contrib/systemd/` into `/usr/lib/systemd/system/` (and `contrib/systemd/gentlsa.conf` into `/usr/lib/tmpfiles.d/`) and run `systemctl daemon-reload`. On FreeBSD, call `gentlsa rollover --resume` from cron or `@reboot` instead.

Certbot should use `certonly` (no `--nginx` / `--apache` installer) so it does not reload in the same run as issuance.

```
#!/bin/sh
# /etc/letsencrypt/renewal-hooks/deploy/gentlsa
set -eu
zone=$(basename "$RENEWED_LINEAGE")
gentlsa rollover "$RENEWED_LINEAGE/cert.pem" "$zone" 443 \
  --cloudflare --reload "systemctl reload nginx" --schedule
```

The same sequence by hand:

1. Issue the new certificate, but do not reload the service yet.
2. Publish the **new** hash next to the old one:
   ```
   gentlsa file /etc/letsencrypt/live/example.com/cert.pem --zone example.com --port 443 --cloudflare
   # or: --nsupdate / --route53 / --google / --azure
   ```
3. Wait at least two TLSA TTLs (and any resolver cache).
4. Reload the service so it presents the new certificate.
5. After another two TTLs, drop the old hash:
   ```
   gentlsa prune example.com 443 --cloudflare
   ```

If the new cert is already live, `generate --cloudflare` still **adds** the live hash instead of overwriting. That does not fix clients that only cached the old record, but it avoids deleting a hash that some resolvers still expect.

`--replace` on `generate` / `file` restores the old one-record overwrite.

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

## Azure DNS

`--azure` publishes TLSA through the Azure Resource Manager DNS API. Create `/etc/gentlsa/azure.cfg` (or `~/.gentlsa/azure.cfg`):

```
[Azure]
tenant_id = <directory id>
client_id = <application id>
client_secret = <client secret>
subscription_id = <subscription id>
resource_group = <resource group>
ttl = 3600
```

`resource_group` is optional. When it is set, zone lookup is limited to that group. When it is omitted, gentlsa lists every DNS zone in the subscription.

`credentials` can point at an Azure service-principal JSON file (`az ad sp create-for-rbac` / SDK-auth shape). A key file carries no resource group or TTL, so `resource_group` and `ttl` are still read from the config file alongside it. A `credentials` path that does not exist is an error rather than a silent fallback to the other keys.

`gentlsa azure --info` prints the resource group in effect, which is the quickest way to check whether lookups are scoped to a group or searching the whole subscription:

```
$ gentlsa azure --info
>>> Azure DNS Information:
Auth: service principal 1a2b3c4d…
Subscription: 00000000-0000-0000-0000-000000000000
Resource group: dns-rg
```

Environment variables override the config file:

| Variable | Use |
|----------|-----|
| `AZURE_TENANT_ID` or `GENTLSA_AZURE_TENANT_ID` | Directory (tenant) ID |
| `AZURE_CLIENT_ID` or `GENTLSA_AZURE_CLIENT_ID` | Application (client) ID |
| `AZURE_CLIENT_SECRET` or `GENTLSA_AZURE_CLIENT_SECRET` | Client secret |
| `AZURE_SUBSCRIPTION_ID` or `GENTLSA_AZURE_SUBSCRIPTION_ID` | Subscription ID |
| `AZURE_RESOURCE_GROUP` or `GENTLSA_AZURE_RESOURCE_GROUP` | Resource group (optional) |
| `GENTLSA_AZURE_CREDENTIALS` or `AZURE_CREDENTIALS` | Path to service-principal JSON |

The principal needs `Microsoft.Network/dnszones/read` plus `Microsoft.Network/dnszones/TLSA/read`, `write`, and `delete` (DNS Zone Contributor, or a custom role with those permissions). Azure only accepts TLSA records on a DNSSEC-signed zone.

```
$ gentlsa azure --listzones
$ gentlsa azure --info
$ gentlsa generate example.com 443 --azure --dryrun
$ gentlsa list example.com 443 --azure --info
$ gentlsa prune example.com 443 --azure --dryrun
```

DigitalOcean DNS is not supported: the official API has no TLSA record type and no DNSSEC.

## Development

```
cargo test
cargo clippy --all-targets -- -D warnings
mandoc -a man/gentlsa.1
mandoc -a man/gentlsa.5
```

CI runs `cargo test --release` and a binary smoke test (`scripts/smoke-test.sh`) on Linux (x86_64 and arm64), macOS (Apple Silicon and Intel), Windows (x86_64 and arm64), and FreeBSD 14 amd64. The FreeBSD job also `pkg add`s the built `.pkg` and re-runs the smoke test on `/usr/local/bin/gentlsa`.

To build local RPM and deb packages (`cargo-generate-rpm` and `cargo-deb` required). Both include the systemd units from `contrib/systemd/`:

```
./scripts/build-rpms.sh
```

To build a local FreeBSD `.pkg` (amd64). On macOS this cross-compiles inside an [Apple container](https://github.com/apple/container) (not Docker). The FreeBSD package is the binary, man pages, license, and README:

```
./scripts/build-pkg.sh
```

Fixture certificate used by the hash tests: `tests/fixtures/test.example.pem`.

Releases are cut by bumping `version` in `Cargo.toml` and pushing a matching tag. [dist](https://github.com/axodotdev/cargo-dist) then builds binaries and installers and publishes the Homebrew formula to [BradKollmyer/homebrew-tap](https://github.com/BradKollmyer/homebrew-tap):

```
# bump version in Cargo.toml and CHANGELOG.md
git commit -am "release: 0.5.1"
git tag v0.5.1
git push && git push --tags
```

## License

BSD-2-Clause. Copyright (c) 2018 Emiel Kollof; Copyright (c) 2026 Brad Kollmyer. See [LICENSE](LICENSE).
