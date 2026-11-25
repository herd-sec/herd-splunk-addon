#!/usr/bin/env bash
# Package TA-herd-security into dist/TA-herd-security-<version>.tgz.
# Splunk wants the tarball's top-level folder to be the app id, and no macOS
# resource-fork files inside it.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
version="$(sed -n 's/^version = //p' "$root/TA-herd-security/default/app.conf" | head -n 1)"
mkdir -p "$root/dist"
out="$root/dist/TA-herd-security-$version.tgz"

COPYFILE_DISABLE=1 tar --exclude='.DS_Store' --exclude='._*' -C "$root" -czf "$out" TA-herd-security
echo "$out"
