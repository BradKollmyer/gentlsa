#!/bin/sh
# Regenerate the checked-in shell completions from a gentlsa binary.
# Usage: scripts/gen-completions.sh [--check] [BIN]
# --check: exit non-zero if the checked-in files are out of date.
set -eu

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
check=0
if [ "${1:-}" = "--check" ]; then
    check=1
    shift
fi
bin="${1:-$root/target/release/gentlsa}"
if [ ! -f "$bin" ] && [ -f "${bin}.exe" ]; then
    bin="${bin}.exe"
fi
if [ ! -f "$bin" ]; then
    echo "binary not found: $bin" >&2
    exit 1
fi

out="$root/contrib/completions"
mkdir -p "$out"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

"$bin" completions bash >"$tmp/gentlsa.bash"
"$bin" completions zsh >"$tmp/_gentlsa"
"$bin" completions fish >"$tmp/gentlsa.fish"

status=0
for f in gentlsa.bash _gentlsa gentlsa.fish; do
    if [ "$check" = 1 ]; then
        if ! cmp -s "$tmp/$f" "$out/$f"; then
            echo "contrib/completions/$f is out of date; run scripts/gen-completions.sh" >&2
            status=1
        fi
    else
        cp "$tmp/$f" "$out/$f"
        echo "wrote contrib/completions/$f"
    fi
done

if [ "$check" = 1 ] && [ "$status" = 0 ]; then
    echo "completions ok"
fi
exit "$status"
