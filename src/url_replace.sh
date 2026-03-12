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

  php <<'PHP' "$input_sql" "$old_domain" "$new_url" "$output_sql"
<?php
if ($argc < 5) {
  fwrite(STDERR, "ERROR: Missing args\n");
  exit(1);
}

$input = $argv[1];
$oldDomain = trim((string)$argv[2]);
$newUrl = rtrim(trim((string)$argv[3]), '/');
$output = $argv[4];

if ($oldDomain === '' || $newUrl === '') {
  fwrite(STDERR, "ERROR: old-domain and new-url are required\n");
  exit(1);
}

if (!preg_match('#^https?://#i', $newUrl)) {
  fwrite(STDERR, "ERROR: new-url must start with http:// or https://\n");
  exit(1);
}

$replaceMap = [
  'http://' . $oldDomain => $newUrl,
  'https://' . $oldDomain => $newUrl,
];

$sql = file_get_contents($input);
if ($sql === false) {
  fwrite(STDERR, "ERROR: Failed to read SQL file\n");
  exit(1);
}

function replaceRecursive($value, array $replaceMap, int &$changes) {
  if (is_string($value)) {
    $updated = strtr($value, $replaceMap);
    if ($updated !== $value) {
      $changes++;
    }
    return $updated;
  }
  if (is_array($value)) {
    foreach ($value as $k => $v) {
      $value[$k] = replaceRecursive($v, $replaceMap, $changes);
    }
    return $value;
  }
  if (is_object($value)) {
    foreach (get_object_vars($value) as $k => $v) {
      $value->$k = replaceRecursive($v, $replaceMap, $changes);
    }
    return $value;
  }
  return $value;
}

function replaceInScalar(string $value, array $replaceMap, int &$changedValues): string {
  if ($value === '') {
    return $value;
  }

  $serialized = @unserialize($value, ['allowed_classes' => false]);
  if ($serialized !== false || $value === 'b:0;') {
    $inner = 0;
    $updated = replaceRecursive($serialized, $replaceMap, $inner);
    if ($inner > 0) {
      $changedValues++;
      return serialize($updated);
    }
    return $value;
  }

  $json = json_decode($value, true);
  if (json_last_error() === JSON_ERROR_NONE && (is_array($json) || is_object($json) || is_string($json))) {
    $inner = 0;
    $updated = replaceRecursive($json, $replaceMap, $inner);
    if ($inner > 0) {
      $encoded = json_encode($updated, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
      if ($encoded !== false) {
        $changedValues++;
        return $encoded;
      }
    }
  }

  $updated = strtr($value, $replaceMap);
  if ($updated !== $value) {
    $changedValues++;
  }
  return $updated;
}

function unescapeMySqlSingleQuoted(string $literal): string {
  $out = '';
  $len = strlen($literal);
  for ($i = 0; $i < $len; $i++) {
    $ch = $literal[$i];
    if ($ch === "\\" && $i + 1 < $len) {
      $n = $literal[$i + 1];
      if ($n === '0') { $out .= "\0"; $i++; continue; }
      if ($n === 'n') { $out .= "\n"; $i++; continue; }
      if ($n === 'r') { $out .= "\r"; $i++; continue; }
      if ($n === 't') { $out .= "\t"; $i++; continue; }
      if ($n === 'b') { $out .= "\x08"; $i++; continue; }
      if ($n === 'Z') { $out .= "\x1A"; $i++; continue; }
      if ($n === "'" || $n === '"' || $n === "\\") { $out .= $n; $i++; continue; }
      $out .= $n;
      $i++;
      continue;
    }
    $out .= $ch;
  }
  return $out;
}

function escapeMySqlSingleQuoted(string $value): string {
  $value = str_replace("\\", "\\\\", $value);
  $value = str_replace("\0", "\\0", $value);
  $value = str_replace("\n", "\\n", $value);
  $value = str_replace("\r", "\\r", $value);
  $value = str_replace("\x1A", "\\Z", $value);
  $value = str_replace("'", "\\'", $value);
  return $value;
}

$out = '';
$len = strlen($sql);
$i = 0;
$changedValues = 0;

while ($i < $len) {
  $ch = $sql[$i];
  if ($ch !== "'") {
    $out .= $ch;
    $i++;
    continue;
  }

  $i++;
  $raw = '';
  while ($i < $len) {
    $c = $sql[$i];
    if ($c === "\\" && $i + 1 < $len) {
      $raw .= $c . $sql[$i + 1];
      $i += 2;
      continue;
    }
    if ($c === "'") {
      $i++;
      break;
    }
    $raw .= $c;
    $i++;
  }

  $decoded = unescapeMySqlSingleQuoted($raw);
  $updated = replaceInScalar($decoded, $replaceMap, $changedValues);
  $out .= "'" . escapeMySqlSingleQuoted($updated) . "'";
}

if (file_put_contents($output, $out) === false) {
  fwrite(STDERR, "ERROR: Failed to write output SQL file\n");
  exit(1);
}

fwrite(STDOUT, "Done. Updated scalar values: {$changedValues}\n");
fwrite(STDOUT, "Output: {$output}\n");
PHP
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
  cleanup() { rm -rf "$tmp_dir"; }
  trap cleanup EXIT

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
