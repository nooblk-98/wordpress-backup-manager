#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  url_replace.sh <input.sql|input.zip> [old-domain] [new-url] [output-file]

Examples:
  ./url_replace.sh database.sql example.com https://example2.com
  ./url_replace.sh full-backup.zip example.com https://example2.com full-backup-updated.zip
  ./url_replace.sh

Behavior:
  - Single script for BOTH input types: .sql and .zip
  - Replaces both http://old-domain and https://old-domain with new-url
  - Interactive mode asks inputs one-by-one
  - If output-file is omitted, updates input file in place
EOF
}

process_sql_file() {
  local input_sql="$1"
  local old_domain="$2"
  local new_url="$3"
  local output_sql="$4"

  if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 command not found" >&2
    exit 1
  fi

  python3 - "$input_sql" "$old_domain" "$new_url" "$output_sql" <<'PY'
import sys

if len(sys.argv) < 5:
    print("ERROR: Missing args", file=sys.stderr)
    sys.exit(1)

input_path, old_domain, new_url, output_path = sys.argv[1:5]
old_domain = old_domain.strip()
new_url = new_url.strip().rstrip('/')

if not old_domain or not new_url:
    print("ERROR: old-domain and new-url are required", file=sys.stderr)
    sys.exit(1)

if not (new_url.startswith("http://") or new_url.startswith("https://")):
    print("ERROR: new-url must start with http:// or https://", file=sys.stderr)
    sys.exit(1)

replacements = {
    f"http://{old_domain}": new_url,
    f"https://{old_domain}": new_url,
}

with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
    sql = fh.read()

def unescape_mysql_single_quoted(s: str) -> str:
    out = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "\\" and i + 1 < n:
            nxt = s[i + 1]
            if nxt == "0": out.append("\0")
            elif nxt == "n": out.append("\n")
            elif nxt == "r": out.append("\r")
            elif nxt == "t": out.append("\t")
            elif nxt == "b": out.append("\x08")
            elif nxt == "Z": out.append("\x1A")
            elif nxt in ["'", '"', "\\"]: out.append(nxt)
            else: out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)

def escape_mysql_single_quoted(s: str) -> str:
    s = s.replace("\\", "\\\\")
    s = s.replace("\0", "\\0")
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\x1A", "\\Z")
    s = s.replace("'", "\\'")
    return s

def apply_replacements(s: str):
    original = s
    for src, dst in replacements.items():
        s = s.replace(src, dst)
    return s, int(s != original)

out = []
i = 0
n = len(sql)
changed_values = 0

while i < n:
    ch = sql[i]
    if ch != "'":
        out.append(ch)
        i += 1
        continue

    i += 1
    raw = []
    while i < n:
        c = sql[i]
        if c == "\\" and i + 1 < n:
            raw.append(c)
            raw.append(sql[i + 1])
            i += 2
            continue
        if c == "'":
            i += 1
            break
        raw.append(c)
        i += 1

    decoded = unescape_mysql_single_quoted("".join(raw))
    updated, changed = apply_replacements(decoded)
    changed_values += changed
    out.append("'" + escape_mysql_single_quoted(updated) + "'")

with open(output_path, "w", encoding="utf-8") as fh:
    fh.write("".join(out))

print(f"Done. Updated scalar values: {changed_values}")
print(f"Output: {output_path}")
PY
}

process_zip_file() {
  local input_zip="$1"
  local old_domain="$2"
  local new_url="$3"
  local output_zip="$4"

  if ! command -v unzip >/dev/null 2>&1; then
  echo "ERROR: unzip command not found" >&2
  exit 1
  fi
  if ! command -v zip >/dev/null 2>&1; then
  echo "ERROR: zip command not found" >&2
  exit 1
  fi

  local tmp_dir
  tmp_dir="$(mktemp -d 2>/dev/null || mktemp -d -t url-replace)"
  trap 'rm -rf -- "$tmp_dir"' RETURN

  echo "Extracting: $input_zip"
  unzip -q "$input_zip" -d "$tmp_dir"

  local sql_file
  sql_file="$(find "$tmp_dir" -type f -name '*.sql' ! -path '*/wp-content/*' | head -n 1 || true)"
  if [[ -z "$sql_file" ]]; then
  echo "ERROR: No SQL file found in zip (outside wp-content/)" >&2
  exit 1
  fi

  echo "Rewriting SQL inside zip: $sql_file"
  process_sql_file "$sql_file" "$old_domain" "$new_url" "$sql_file"

  local tmp_zip="$tmp_dir/repacked.zip"
  echo "Repacking zip: $output_zip"
  (
  cd "$tmp_dir"
  rm -f "$tmp_zip"
  zip -qr "$tmp_zip" .
  )
  cp -f "$tmp_zip" "$output_zip"
  echo "Done: $output_zip"
  trap - RETURN
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

while true; do
  if [[ -z "$INPUT_FILE" ]]; then
    read -r -p "Input backup file (.sql or .zip): " INPUT_FILE
  fi

  if [[ ! -f "$INPUT_FILE" ]]; then
    echo "ERROR: Input file not found: $INPUT_FILE" >&2
    INPUT_FILE=""
    continue
  fi

  ext_check="${INPUT_FILE##*.}"
  ext_check="$(echo "$ext_check" | tr '[:upper:]' '[:lower:]')"
  if [[ "$ext_check" != "sql" && "$ext_check" != "zip" ]]; then
    echo "ERROR: Unsupported input type '$ext_check'. Use .sql or .zip" >&2
    INPUT_FILE=""
    continue
  fi

  break
done

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
  echo "Processing SQL backup..."
  process_sql_file "$INPUT_FILE" "$OLD_DOMAIN" "$NEW_URL" "$OUTPUT_FILE"
  exit 0
fi

if [[ "$EXT" == "zip" ]]; then
  echo "Processing ZIP backup..."
  process_zip_file "$INPUT_FILE" "$OLD_DOMAIN" "$NEW_URL" "$OUTPUT_FILE"
  exit 0
fi

echo "ERROR: Unsupported input type '$EXT'. Use .sql or .zip" >&2
exit 1
