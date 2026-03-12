#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_REPLACER="$SCRIPT_DIR/replace_sql_urls.sh"
ZIP_REPLACER="$SCRIPT_DIR/replace_backup_zip_urls.sh"

usage() {
  cat <<'EOF'
Usage:
  replace_backup_urls.sh <input.sql|input.zip> [old-domain] [new-url] [output-file]

Examples:
  replace_backup_urls.sh database.sql example.com https://example2.com
  replace_backup_urls.sh full-backup.zip example.com https://example2.com full-backup-updated.zip
  replace_backup_urls.sh full-backup.zip

Behavior:
  - Supports BOTH input types: .sql and .zip
  - Replaces both http://old-domain and https://old-domain with new-url
  - If old-domain/new-url are omitted, prompts interactively
  - If output-file is omitted, updates input file in place
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -gt 4 ]]; then
  usage
  exit 1
fi

INPUT_FILE="${1:-}"
OLD_DOMAIN="${2:-}"
NEW_URL="${3:-}"

if [[ -z "$INPUT_FILE" ]]; then
  read -r -p "Input backup file (.sql or .zip): " INPUT_FILE
fi

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "ERROR: Input file not found: $INPUT_FILE" >&2
  exit 1
fi

if [[ -z "$OLD_DOMAIN" ]]; then
  read -r -p "Old domain (without protocol, e.g. example.com): " OLD_DOMAIN
fi

if [[ -z "$NEW_URL" ]]; then
  read -r -p "New URL (e.g. https://example2.com): " NEW_URL
fi

OUTPUT_FILE="${4:-}"
if [[ -z "$OUTPUT_FILE" ]]; then
  read -r -p "Output file path (Enter = overwrite input): " OUTPUT_FILE
  if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="$INPUT_FILE"
  fi
fi

OLD_DOMAIN="$(echo "$OLD_DOMAIN" | tr -d '[:space:]')"
NEW_URL="$(echo "$NEW_URL" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"

if [[ -z "$OLD_DOMAIN" || -z "$NEW_URL" ]]; then
  echo "ERROR: old-domain and new-url are required" >&2
  exit 1
fi

if [[ ! "$NEW_URL" =~ ^https?:// ]]; then
  echo "ERROR: new-url must start with http:// or https://" >&2
  exit 1
fi

EXT="${INPUT_FILE##*.}"
EXT="$(echo "$EXT" | tr '[:upper:]' '[:lower:]')"

if [[ "$EXT" == "sql" ]]; then
  if [[ ! -x "$SQL_REPLACER" ]]; then
    echo "ERROR: Missing or non-executable script: $SQL_REPLACER" >&2
    echo "Run: chmod +x '$SQL_REPLACER' '$SCRIPT_DIR/replace_backup_urls.sh'" >&2
    exit 1
  fi

  echo "Processing SQL backup..."
  "$SQL_REPLACER" "$INPUT_FILE" "$OLD_DOMAIN" "$NEW_URL" "$OUTPUT_FILE"
  exit 0
fi

if [[ "$EXT" == "zip" ]]; then
  if [[ ! -x "$ZIP_REPLACER" ]]; then
    echo "ERROR: Missing or non-executable script: $ZIP_REPLACER" >&2
    echo "Run: chmod +x '$ZIP_REPLACER' '$SCRIPT_DIR/replace_backup_urls.sh'" >&2
    exit 1
  fi

  echo "Processing ZIP backup..."
  "$ZIP_REPLACER" "$INPUT_FILE" "$OLD_DOMAIN" "$NEW_URL" "$OUTPUT_FILE"
  exit 0
fi

echo "ERROR: Unsupported input type '$EXT'. Use .sql or .zip" >&2
exit 1
