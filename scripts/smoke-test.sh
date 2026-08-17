#!/bin/sh
# Smoke-test a gentlsa binary: --help, --version, and the fixture cert.
# Usage: scripts/smoke-test.sh [PATH]
set -eu

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
bin="${1:-$root/target/release/gentlsa}"
if [ ! -f "$bin" ] && [ -f "${bin}.exe" ]; then
    bin="${bin}.exe"
fi
if [ ! -f "$bin" ]; then
    echo "binary not found: $bin" >&2
    exit 1
fi

cert="$root/tests/fixtures/test.example.pem"
hash="ff94ad7dfafffed26e98150947dd8b1a7d981fabf90740c574685c81d487b9a8"

"$bin" --help >/dev/null
"$bin" rollover --help | grep -q -- '--reload' || {
    echo "expected rollover --help to mention --reload" >&2
    exit 1
}
"$bin" rollover --help | grep -q -- '--resume' || {
    echo "expected rollover --help to mention --resume" >&2
    exit 1
}
"$bin" verify --help | grep -q -- '--warn' || {
    echo "expected verify --help to mention --warn" >&2
    exit 1
}
"$bin" verify --help | grep -q -- '--critical' || {
    echo "expected verify --help to mention --critical" >&2
    exit 1
}
"$bin" generate --help | grep -q -- '--starttls' || {
    echo "expected generate --help to mention --starttls" >&2
    exit 1
}
for shell in bash zsh fish; do
    "$bin" completions "$shell" | grep -q gentlsa || {
        echo "expected $shell completions to mention gentlsa" >&2
        exit 1
    }
done
"$bin" --version
out="$("$bin" file "$cert" --port 443)"
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q "$hash" || {
    echo "expected SPKI SHA-256 $hash in output" >&2
    exit 1
}
printf '%s\n' "$out" | grep -q "_443._tcp TLSA 3 1 1" || {
    echo "expected TLSA 3 1 1 record line" >&2
    exit 1
}
json="$("$bin" --json file "$cert" --port 443)"
printf '%s\n' "$json"
printf '%s\n' "$json" | grep -q '"command": "file"' || {
    echo "expected JSON command field" >&2
    exit 1
}
printf '%s\n' "$json" | grep -q "$hash" || {
    echo "expected SPKI SHA-256 $hash in JSON output" >&2
    exit 1
}
if printf '%s\n' "$json" | grep -q '>>> Certificate'; then
    echo "JSON output should not include text headers" >&2
    exit 1
fi
echo "smoke test passed: $bin"
