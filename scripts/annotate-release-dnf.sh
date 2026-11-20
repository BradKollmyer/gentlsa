#!/usr/bin/env bash
# Insert Fedora/RHEL dnf install instructions into a cargo-dist release body.
# Dist writes the shell, PowerShell, and Homebrew installers only. The RPMs
# are attached later by build-rpms, so this runs after that upload.
#
# Usage: annotate-release-dnf.sh TAG [INFILE]
# Writes the notes to stdout. INFILE defaults to stdin.
set -euo pipefail

tag="${1:?usage: annotate-release-dnf.sh TAG [INFILE]}"
infile="${2:--}"
repo="${GITHUB_REPOSITORY:-BradKollmyer/gentlsa}"

if [[ "$infile" == "-" ]]; then
    notes="$(cat)"
else
    notes="$(cat "$infile")"
fi

if printf '%s\n' "$notes" | grep -q 'sudo dnf install'; then
    printf '%s\n' "$notes"
    exit 0
fi

insert="$(mktemp)"
trap 'rm -f "$insert"' EXIT

cat > "$insert" <<EOF
### Install on Fedora / RHEL with dnf

\`\`\`sh
# x86_64
sudo dnf install https://github.com/${repo}/releases/download/${tag}/gentlsa.x86_64.rpm

# aarch64
sudo dnf install https://github.com/${repo}/releases/download/${tag}/gentlsa.aarch64.rpm
\`\`\`

The RPM installs \`/usr/bin/gentlsa\`, man pages, and the systemd units. If you use \`rollover\`:

\`\`\`sh
sudo systemctl enable --now gentlsa-resume.timer
\`\`\`

EOF

if printf '%s\n' "$notes" | grep -q '^## Download '; then
    awk -v insert_file="$insert" '
        /^## Download / && !inserted {
            while ((getline line < insert_file) > 0) print line
            inserted = 1
        }
        { print }
    ' <<< "$notes"
else
    printf '%s\n\n' "$notes"
    cat "$insert"
fi
