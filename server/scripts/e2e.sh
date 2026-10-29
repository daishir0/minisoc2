#!/usr/bin/env bash
# Run the E2E suite against E2E_BASE_URL with a throwaway admin, then remove only what the test created.
set -euo pipefail
cd "$(dirname "$0")/.."
E="e2e-$(date +%s)@example.invalid"
PW="$(openssl rand -hex 16)"
npx tsx scripts/e2e-admin.ts create "$E" "$PW" >/dev/null
trap 'npx tsx scripts/e2e-admin.ts delete "$E" >/dev/null; npx tsx scripts/e2e-cleanup.ts >/dev/null' EXIT
E2E_ADMIN_EMAIL="$E" E2E_ADMIN_PASSWORD="$PW" npx playwright test "$@"
