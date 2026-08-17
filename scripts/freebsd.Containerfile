# Cross-compile gentlsa for x86_64-unknown-freebsd with cargo-zigbuild.
# Used by scripts/build-pkg.sh via Apple's `container` CLI (not Docker).
FROM rust:1-bookworm

RUN rustup target add x86_64-unknown-freebsd

# 0.15+ ships FreeBSD libc headers (needed by ring). Tarball: zig-<arch>-linux-<ver>.tar.xz
ARG ZIG_VERSION=0.15.2
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64) zig_arch=x86_64 ;; \
      aarch64) zig_arch=aarch64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-linux-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /opt; \
    ln -s "/opt/zig-${zig_arch}-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig; \
    zig version

RUN cargo install cargo-zigbuild --locked
WORKDIR /io
