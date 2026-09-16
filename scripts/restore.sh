#!/usr/bin/env bash
# PhaseOne10841 restore — Postgres + policy from a backup directory
# Usage: ./scripts/restore.sh backups/YYYYMMDD-HHMMSS
# Veracity Integrity LLC · https://VeracityIntegrity.com
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-}"
if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
  echo "Usage: $0 <backup-dir>" >&2
  echo "Example: $0 backups/20260916-213000" >&2
  exit 1
fi

DATABASE_URL="${DATABASE_URL:-postgres://phaseone:phaseone@localhost:5432/phaseone}"
SQL="$SRC/phaseone-postgres.sql"

echo "PhaseOne10841 restore from $SRC"
echo "WARNING: This replaces database contents and overwrites policy/default-policy.yaml"
read -r -p "Type RESTORE to continue: " confirm
if [ "$confirm" != "RESTORE" ]; then
  echo "Aborted."
  exit 1
fi

if [ -f "$SQL" ] && ! grep -q '^-- skipped' "$SQL"; then
  if command -v docker >/dev/null 2>&1 && docker compose -f "$ROOT/docker-compose.yml" ps postgres 2>/dev/null | grep -q Up; then
    # Drop+recreate public schema then restore
    docker compose -f "$ROOT/docker-compose.yml" exec -T postgres \
      psql -U phaseone -d phaseone -v ON_ERROR_STOP=1 \
      -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
    docker compose -f "$ROOT/docker-compose.yml" exec -T postgres \
      psql -U phaseone -d phaseone -v ON_ERROR_STOP=1 < "$SQL"
  elif command -v psql >/dev/null 2>&1; then
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 < "$SQL"
  else
    echo "ERROR: need docker compose postgres or psql" >&2
    exit 1
  fi
else
  echo "WARN: skipping DB restore (missing or skipped dump)" >&2
fi

if [ -f "$SRC/policy/default-policy.yaml" ]; then
  cp -a "$ROOT/policy/default-policy.yaml" "$ROOT/policy/default-policy.yaml.bak.pre-restore.$(date +%s)" 2>/dev/null || true
  cp -a "$SRC/policy/default-policy.yaml" "$ROOT/policy/default-policy.yaml"
  echo "✓ Restored policy/default-policy.yaml"
fi

echo "✓ Restore finished. Restart gateway/dashboard if running."
echo "Veracity Integrity LLC · https://VeracityIntegrity.com"
