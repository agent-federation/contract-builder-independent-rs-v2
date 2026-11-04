#!/usr/bin/env bash
# Checker-identity two-way closure self-check (brief §4.4.1).
#
# Direction (a): change one byte of one INCLUDED closure file, rebuild, and
#                recompute — the digest MUST change.
# Direction (b): change a file OUTSIDE the closure, rebuild, and recompute —
#                the digest MUST NOT change.
#
# The check runs on a copy of the implementation checkout in a temporary
# directory so the working tree stays clean. It builds the copy, extracts
# `verifier.implementationDigest` from a report on a fixture, applies the
# mutation, rebuilds, and compares.
#
# Usage: scripts/checker-identity-selfcheck.sh [fixture-dir]
# Exit 0 on success; non-zero with a description on any failure.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="${1:-$ROOT/pap/fixtures/pap-v0.1/F01-unchanged}"
TRUST_POLICY="$ROOT/pap/fixtures/pap-v0.1/trust-policy/unsigned-valid.json"
WORK="$(mktemp -d /tmp/pap-selfcheck.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

results="$WORK/result.txt"
: > "$results"

echo "== Checker-identity two-way self-check =="
echo "checkout copy: $WORK/impl"

# --- copy the implementation (tracked build inputs + test inputs) ----------
mkdir -p "$WORK/impl/src"
cp "$ROOT/Cargo.toml" "$WORK/impl/Cargo.toml"
cp "$ROOT/build.rs" "$WORK/impl/build.rs"
cp "$ROOT"/src/*.rs "$WORK/impl/src/"
# files outside the closure that must not affect the digest:
printf 'note: exists only for self-check direction (b)\n' > "$WORK/impl/README-selfcheck.md"
echo "// test-only file outside the closure (self-check direction b)" > "$WORK/impl/tests-placeholder.rs"

build_digest() {
  (cd "$WORK/impl" && cargo build --release --offline >/dev/null 2>&1 || cargo build --release >/dev/null)
  local out
  out=$( (cd "$FIXTURE" && "$WORK/impl/target/release/pap" verify . \
      --trust-policy "$TRUST_POLICY" --format json --now 2026-11-02T00:00:00Z) )
  printf '%s\n' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verifier"]["implementationDigest"])'
}

# --- baseline -------------------------------------------------------------
D0=$(build_digest)
echo "baseline implementationDigest: $D0"

# --- direction (a): one byte of one INCLUDED file -------------------------
printf '\n' >> "$WORK/impl/src/jcs.rs"   # one byte change to src/jcs.rs
D1=$(build_digest)
echo "after included-file change:   $D1"
if [ "$D0" = "$D1" ]; then
  echo "FAIL direction (a): digest did not change after closing-file mutation"
  exit 1
else
  echo "PASS direction (a): digest changed"
fi

# --- direction (b): a file OUTSIDE the closure ----------------------------
printf 'more text\n' >> "$WORK/impl/README-selfcheck.md"
D2=$(build_digest)
echo "after outside-file change:    $D2"
if [ "$D1" != "$D2" ]; then
  echo "FAIL direction (b): digest changed after an outside-closure mutation"
  exit 1
else
  echo "PASS direction (b): digest unchanged"
fi

echo "== result =="
echo "D0 (baseline)              = $D0"
echo "D1 (included file changed) = $D1"
echo "D2 (outside file changed)  = $D2"
[ "$D0" != "$D1" ] && [ "$D1" = "$D2" ] && echo "SELF-CHECK PASSED"
