#!/bin/sh
# Validate checked-in man pages (existence, required topics, optional mandoc lint).
set -eu

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
page1="$root/man/gentlsa.1"
page5="$root/man/gentlsa.5"

for page in "$page1" "$page5"; do
    if [ ! -f "$page" ]; then
        echo "missing $page" >&2
        exit 1
    fi
done

need() {
    file="$1"
    shift
    for needle in "$@"; do
        if ! grep -q "$needle" "$file"; then
            echo "$file: expected to mention $needle" >&2
            exit 1
        fi
    done
}

need "$page1" generate verify list prune rollover cloudflare nsupdate route53 google azure completions
need "$page5" cloudflare.cfg nsupdate.cfg route53.cfg google.cfg azure.cfg

if command -v mandoc >/dev/null 2>&1; then
    # "referenced manual not found" is expected before the pages are installed.
    lint="$(mandoc -T lint -W warning "$page1" "$page5" 2>&1 | grep -v 'referenced manual not found' || true)"
    if [ -n "$lint" ]; then
        printf '%s\n' "$lint" >&2
        exit 1
    fi
fi

echo "man pages ok"
