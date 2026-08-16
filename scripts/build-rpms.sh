#!/usr/bin/env bash
# Build Fedora RPMs and Ubuntu/Debian debs from dist Linux archives,
# or from a local cargo build.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
rpm_out="${RPM_OUT:-$root/target/generate-rpm}"
deb_out="${DEB_OUT:-$root/target/debian}"
mkdir -p "$rpm_out" "$deb_out" target/release

package_bin() {
    local bin="$1"
    local triple="$2"
    local rpm_arch="$3"
    local deb_arch="$4"

    mkdir -p "target/${triple}/release"
    cp "$bin" target/release/gentlsa
    cp "$bin" "target/${triple}/release/gentlsa"
    chmod 755 target/release/gentlsa "target/${triple}/release/gentlsa"

    cargo generate-rpm --auto-req disabled --arch "$rpm_arch" \
        -o "$rpm_out/gentlsa-${version}-1.${rpm_arch}.rpm"
    cp "$rpm_out/gentlsa-${version}-1.${rpm_arch}.rpm" "$rpm_out/gentlsa.${rpm_arch}.rpm"
    echo "wrote $rpm_out/gentlsa-${version}-1.${rpm_arch}.rpm"

    cargo deb --no-build --no-strip --target "$triple" \
        --output "$deb_out/gentlsa_${version}-1_${deb_arch}.deb"
    cp "$deb_out/gentlsa_${version}-1_${deb_arch}.deb" "$deb_out/gentlsa.${deb_arch}.deb"
    echo "wrote $deb_out/gentlsa_${version}-1_${deb_arch}.deb"
}

if [[ "${1:-}" == "--from-artifacts" ]]; then
    artifacts="${2:?usage: $0 --from-artifacts DIR}"
    packed=0
    for spec in \
        x86_64-unknown-linux-gnu:x86_64:amd64 \
        aarch64-unknown-linux-gnu:aarch64:arm64
    do
        triple="${spec%%:*}"
        rest="${spec#*:}"
        rpm_arch="${rest%%:*}"
        deb_arch="${rest##*:}"
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
        package_bin "$bin" "$triple" "$rpm_arch" "$deb_arch"
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
        x86_64 | amd64) package_bin target/release/gentlsa x86_64-unknown-linux-gnu x86_64 amd64 ;;
        aarch64 | arm64) package_bin target/release/gentlsa aarch64-unknown-linux-gnu aarch64 arm64 ;;
        *)
            echo "unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
fi
