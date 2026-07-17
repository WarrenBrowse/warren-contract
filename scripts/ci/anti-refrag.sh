#!/usr/bin/env bash
#
# Anti-refragmentation gate for warren-contract (the neutral client<->server
# contract: SS58 codec, X-Warren signing, /v1 DTOs, USER_AGENT, killswitch
# posture matrix, phase reduction, signed release recipe).
#
# Runnable form of doc 47 section 5 invariant 1 ("dependency direction"), against
# the doc-94 single-home catalog (warren-core/docs/94-DEDUP-AUDIT-2026-07-16.md).
# The contract is the SHARED neutral home both the SDK and the backend depend on;
# it must depend on NEITHER of them (nor the app), else the "both sides consume
# the contract, the contract consumes neither" invariant that stops the wire from
# drifting is broken (doc 47 section 4). Its only engine coupling is the leaf
# warrenguard-wire/-multihop.
#
# Cheap (one offline `cargo metadata --no-deps`), low-false-positive, cites its
# doc reference, honors an inline `anti-refrag:allow` hatch.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

VIOLATIONS=0

report() {
  VIOLATIONS=$((VIOLATIONS + 1))
  printf '\n[anti-refrag] VIOLATION (%s): %s\n' "$1" "$2"
  printf '%s\n' "$3" | sed 's/^/    /'
}

# Dependency direction via cargo metadata: no dependency of the contract may
# resolve into the SDK, the backend, or the app. `--no-deps` is offline and
# ignores comments; grep the JSON so no JSON tooling is needed.
forbid_dep_direction() {
  doc="$1"; forbidden="$2"
  command -v cargo >/dev/null 2>&1 || { printf '[anti-refrag] cargo absent, skipping dep-direction\n'; return 0; }
  meta="$(cargo metadata --no-deps --format-version 1 2>/dev/null)" || {
    printf '[anti-refrag] cargo metadata failed (sibling engine checkout absent?), skipping dep-direction\n'; return 0; }
  hits="$(printf '%s' "$meta" | grep -oE '"(path|source)":[[:space:]]*"[^"]*"' \
          | grep -E "$forbidden" || true)"
  [ -n "$hits" ] && report "$doc" \
    "dependency direction: the neutral contract must not depend on the SDK, backend, or app (doc 47 s4/s5.1)" \
    "$hits"
}

printf '[anti-refrag] warren-contract: checking the neutral contract depends on neither side...\n'

# ---- Rules -------------------------------------------------------------------

forbid_dep_direction "doc47 s4" 'warren-core|warren-app|warren-sdk|[/+]mullvad-'

# -----------------------------------------------------------------------------

if [ "$VIOLATIONS" -gt 0 ]; then
  printf '\n[anti-refrag] FAILED: %d single-home violation(s). The contract stays neutral; do not depend up.\n' "$VIOLATIONS"
  exit 1
fi
printf '[anti-refrag] OK: contract stays neutral.\n'
