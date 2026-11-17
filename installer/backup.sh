#!/usr/bin/env bash
# Create an encrypted Tunnelstead backup now.
# Usage: sudo backup.sh [--copy-to DIR]
# The passphrase is asked for (or taken from TUNNELSTEAD_BACKUP_PASSPHRASE). Without it the backup cannot be restored.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)" >&2; exit 1; }
COPY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --copy-to) COPY="${2:?--copy-to needs a directory}"; shift 2 ;;
    -h|--help) sed -n '2,4p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
out="$(tunnelstead-cli backup)"
echo "$out"
if [[ -n "$COPY" ]]; then
  f="$(sed -n 's/^Backup written: \(.*\) (.*$/\1/p' <<<"$out")"
  install -d -m 0700 "$COPY" && install -m 0600 "$f" "$COPY/" && echo "Copied to $COPY/$(basename "$f")"
fi
