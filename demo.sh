#!/usr/bin/env bash
# Demo script for recording an asciinema cast of rop-forge (PRD.md Phase 7).
#
# NOT run automatically by anything — this is meant to be recorded
# interactively, e.g.:
#   asciinema rec rop-forge-demo.cast --command "./demo.sh"
# from inside the devcontainer (see CONTEXT.md's "How to run anything").
#
# Walks through 3 tiers, from PRD.md's own graduated protection ladder:
#   - fixture1_none: simplest case, no protections
#   - fixture4_nx_pie: ASLR/PIE defeated via a real leak
#   - fixture5_nx_pie_canary: the hardest tier, PIE + canary together
# Each demonstrates protection detection, then a full automated exploit
# with live shell verification.

set -e

pause() { read -rp "  [press enter to continue] " _; }

echo "=== rop-forge demo: three protection tiers, fully automated ==="
echo

echo "--- Tier 1: no protections (fixture1_none) ---"
rop-forge fixtures/build/fixture1_none --stage analyzer
pause
rop-forge fixtures/build/fixture1_none --stage exploit --run
pause

echo
echo "--- Tier 4: NX + PIE, defeated via a real ASLR leak (fixture4_nx_pie) ---"
rop-forge fixtures/build/fixture4_nx_pie --stage analyzer
pause
rop-forge fixtures/build/fixture4_nx_pie \
  --server fixtures/build/fixture4_nx_pie_server \
  --stage exploit --run
pause

echo
echo "--- Tier 5: NX + PIE + canary, the hardest tier (fixture5_nx_pie_canary) ---"
rop-forge fixtures/build/fixture5_nx_pie_canary --stage analyzer
pause
rop-forge fixtures/build/fixture5_nx_pie_canary \
  --server fixtures/build/fixture5_nx_pie_canary_server \
  --stage exploit --run

echo
echo "=== done — all three tiers: real, live shells, fully automated ==="