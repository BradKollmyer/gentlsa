#!/usr/bin/env bash
# Build Fedora/RHEL RPMs from dist Linux archives, or from a local cargo build.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
out_dir="${RPM_OUT:-$root/target/generate-rpm}"
mkdir -p "$out_dir" target/release

package_bin() {
    local bin="$1"
    local arch="$2"
    local dest="target/release/gentlsa"

    cp "$bin" "$dest"
    chmod 755 "$dest"

    cargo generate-rpm --auto-req disabled \
        -o "$out_dir/gentlsa-${version}-1.${arch}.rpm"
    cp "$out_dir/gentlsa-${version}-1.${arch}.rpm" "$out_dir/gentlsa.${arch}.rpm"
    echo "wrote $out_dir/gentlsa-${version}-1.${arch}.rpm"
}

if [[ "${1:-}" == "--from-artifacts" ]]; then
    artifacts="${2:?usage: $0 --from-artifacts DIR}"
    packed=0
    for triple_arch in x86_64-unknown-linux-gnu:x86_64 aarch64-unknown-linux-gnu:aarch64; do
        triple="${triple_arch%%:*}"
        arch="${triple_arch##*:}"
        archive="$artifacts/gentlsa-${triple}.tar.xz"
        if [[ ! -f "$archive" ]]; then
            echo "skip missing $archive" >&2
            continue
        fi
        tmp="$(mktemp -d)"
        tar -xJf "$archive" -C "$tmp"
        bin="$(find "$tmp" -type f -name gentlsa | head -1)"
        if [[ -z "$bin" ]]; then
            echo "no gentlsa binary in $archive" >&2
            rm -rf "$tmp"
            exit 1
        fi
        package_bin "$bin" "$arch"
        rm -rf "$tmp"
        packed=$((packed + 1))
    done
    if [[ "$packed" -eq 0 ]]; then
        echo "no Linux archives found in $artifacts" >&2
        exit 1
    fi
else
    cargo build --release
    case "$(uname -m)" in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=aarch64 ;;
        *)
            echo "unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
    package_bin target/release/gentlsa "$arch"
fi
