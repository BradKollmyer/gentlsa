#!/usr/bin/env bash
# Build a FreeBSD .pkg (amd64) from a FreeBSD binary.
#
#   ./scripts/build-pkg.sh
#     macOS: cross-compile inside an Apple container, then wrap as .pkg
#     Linux: cargo-zigbuild on the host
#     FreeBSD: cargo build --release
#
#   ./scripts/build-pkg.sh --from-bin PATH
#     Wrap an existing FreeBSD binary (used by CI after zigbuild).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
comment="$(sed -n 's/^description = "\(.*\)"/\1/p' Cargo.toml | head -1)"
pkg_out="${PKG_OUT:-$root/target/freebsd}"
triple="x86_64-unknown-freebsd"
image="${FREEBSD_BUILDER_IMAGE:-gentlsa-freebsd-builder}"
mkdir -p "$pkg_out"

package_bin() {
    local bin="$1"
    python3 - "$bin" "$version" "$comment" "$pkg_out" "$root" <<'PY'
import hashlib, json, os, sys, tarfile

bin_path, version, comment, pkg_out, root = sys.argv[1:]
license_path = os.path.join(root, "LICENSE")
readme_path = os.path.join(root, "README.md")

files = [
    ("/usr/local/bin/gentlsa", bin_path, 0o755),
    ("/usr/local/share/licenses/gentlsa/LICENSE", license_path, 0o644),
    ("/usr/local/share/doc/gentlsa/README.md", readme_path, 0o644),
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def file_size(path):
    return os.stat(path).st_size


mtime = int(os.environ.get("SOURCE_DATE_EPOCH", "0")) or None
manifest_files = {}
flatsize = 0
for dest, src, mode in files:
    digest = sha256_file(src)
    manifest_files[dest] = {
        "sum": f"1${digest}",
        "uname": "root",
        "gname": "wheel",
        "perm": f"{mode:04o}",
    }
    if mtime is not None:
        manifest_files[dest]["mtime"] = mtime
    flatsize += file_size(src)

pkgdata = {
    "name": "gentlsa",
    "origin": "dns/gentlsa",
    "version": version,
    "comment": comment,
    "desc": comment,
    "maintainer": "Brad Kollmyer <https://github.com/BradKollmyer>",
    "www": "https://github.com/BradKollmyer/gentlsa",
    "abi": "FreeBSD:14:amd64",
    "arch": "freebsd:14:x86:64",
    "prefix": "/usr/local",
    "flatsize": flatsize,
    "licenselogic": "single",
    "licenses": ["BSD2CLAUSE"],
    "categories": ["dns"],
    "shlibs_required": ["libc.so.7"],
}

os.makedirs(pkg_out, exist_ok=True)
stage = os.path.join(pkg_out, ".stage")
os.makedirs(stage, exist_ok=True)
compact_path = os.path.join(stage, "+COMPACT_MANIFEST")
manifest_path = os.path.join(stage, "+MANIFEST")
with open(compact_path, "w", encoding="utf-8") as f:
    json.dump(pkgdata, f, separators=(",", ":"))
    f.write("\n")
pkgdata["files"] = manifest_files
with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(pkgdata, f, separators=(",", ":"))
    f.write("\n")

versioned = os.path.join(pkg_out, f"gentlsa-{version}.amd64.pkg")
stable = os.path.join(pkg_out, "gentlsa.amd64.pkg")


def add(tar, path, arcname, mode=0o644):
    info = tar.gettarinfo(path, arcname=arcname)
    # Python strips a leading /; FreeBSD pkg members keep it.
    info.name = arcname
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "wheel"
    if mtime is not None:
        info.mtime = mtime
    with open(path, "rb") as fh:
        tar.addfile(info, fh)


with tarfile.open(versioned, mode="w:xz", format=tarfile.USTAR_FORMAT) as tar:
    add(tar, compact_path, "+COMPACT_MANIFEST")
    add(tar, manifest_path, "+MANIFEST")
    for dest, src, mode in files:
        add(tar, src, dest, mode)

# Stable name for the GitHub "latest" download URL.
if os.path.exists(stable):
    os.remove(stable)
os.link(versioned, stable)
print(f"wrote {versioned}")
PY
}

build_bin_macos() {
    if ! command -v container >/dev/null 2>&1; then
        echo "Apple container CLI not found (brew install container)" >&2
        exit 1
    fi
    if ! container system status 2>/dev/null | grep -q 'running'; then
        echo "starting Apple container system..." >&2
        container system start
    fi

    echo "building image $image (cargo-zigbuild + FreeBSD target)..." >&2
    container build \
        --memory 4G \
        --tag "$image" \
        --file "$root/scripts/freebsd.Containerfile" \
        "$root/scripts"

    container volume create gentlsa-cargo-registry >/dev/null 2>&1 || true
    echo "cross-compiling $triple in Apple container..." >&2
    container run --remove \
        --memory 4G \
        --cpus 4 \
        --volume "$root:/io" \
        --volume gentlsa-cargo-registry:/usr/local/cargo/registry \
        --workdir /io \
        "$image" \
        cargo zigbuild --release --locked --target "$triple"
}

build_bin_linux() {
    if ! command -v cargo-zigbuild >/dev/null 2>&1 && ! cargo zigbuild --help >/dev/null 2>&1; then
        echo "cargo-zigbuild is required on Linux (and a zig toolchain)" >&2
        exit 1
    fi
    rustup target add "$triple"
    cargo zigbuild --release --locked --target "$triple"
}

if [[ "${1:-}" == "--from-bin" ]]; then
    bin="${2:?usage: $0 --from-bin PATH}"
    if [[ ! -f "$bin" ]]; then
        echo "binary not found: $bin" >&2
        exit 1
    fi
    package_bin "$bin"
else
    case "$(uname -s)" in
        Darwin) build_bin_macos ;;
        Linux) build_bin_linux ;;
        FreeBSD)
            cargo build --release --locked
            mkdir -p "target/${triple}/release"
            cp target/release/gentlsa "target/${triple}/release/gentlsa"
            ;;
        *)
            echo "unsupported host: $(uname -s)" >&2
            exit 1
            ;;
    esac
    bin="target/${triple}/release/gentlsa"
    if [[ ! -f "$bin" ]]; then
        echo "expected FreeBSD binary at $bin" >&2
        exit 1
    fi
    package_bin "$bin"
fi
