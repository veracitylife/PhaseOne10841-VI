#!/usr/bin/env bash
# PhaseOne10841 backup — Postgres dump + policy YAML copies
# Veracity Integrity LLC · https://VeracityIntegrity.com
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${PHASEONE_BACKUP_DIR:-$ROOT/backups}/$STAMP"
mkdir -p "$OUT_DIR"

DATABASE_URL="${DATABASE_URL:-postgres://phaseone:phaseone@localhost:5432/phaseone}"

echo "PhaseOne10841 backup → $OUT_DIR"

# Prefer docker compose postgres if available
if command -v docker >/dev/null 2>&1 && docker compose -f "$ROOT/docker-compose.yml" ps postgres 2>/dev/null | grep -q healthy; then
  docker compose -f "$ROOT/docker-compose.yml" exec -T postgres \
    pg_dump -U phaseone -d phaseone --no-owner --format=plain \
    > "$OUT_DIR/phaseone-postgres.sql"
elif command -v pg_dump >/dev/null 2>&1; then
  pg_dump "$DATABASE_URL" --no-owner --format=plain > "$OUT_DIR/phaseone-postgres.sql"
else
  echo "WARN: neither docker compose postgres nor pg_dump available; skipping DB dump" >&2
  echo "-- skipped: install postgresql-client or run with compose up" > "$OUT_DIR/phaseone-postgres.sql"
fi

mkdir -p "$OUT_DIR/policy"
cp -a "$ROOT/policy/default-policy.yaml" "$OUT_DIR/policy/" 2>/dev/null || true
if [ -d "$ROOT/policy/backups" ]; then
  cp -a "$ROOT/policy/backups" "$OUT_DIR/policy/" 2>/dev/null || true
fi
if [ -d "$ROOT/rules" ]; then
  mkdir -p "$OUT_DIR/rules"
  cp -a "$ROOT/rules/"*.yaml "$OUT_DIR/rules/" 2>/dev/null || true
fi

# Manifest
{
  echo "product=PhaseOne10841"
  echo "vendor=Veracity Integrity LLC"
  echo "created=$STAMP"
  echo "database_url_host=$(echo "$DATABASE_URL" | sed -E 's|.*@([^/]+)/.*|\1|')"
} > "$OUT_DIR/MANIFEST.txt"

echo "✓ Backup complete: $OUT_DIR"
echo "  - phaseone-postgres.sql"
echo "  - policy/ (+ backups if present)"
echo "  - rules/*.yaml"
