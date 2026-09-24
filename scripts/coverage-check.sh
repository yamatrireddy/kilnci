#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Enforces coverage floors (coding-standards §10).
# usage: coverage-check.sh <coverage.out> <overall-floor> <critical-floor> <critical-pkg-substr>...
# Critical packages are only checked once they exist, so the floor applies from
# the first commit that adds them.
set -euo pipefail

profile=$1; overall_floor=$2; critical_floor=$3; shift 3

total=$(go tool cover -func="$profile" | awk '/^total:/ {sub("%","",$3); print $3}')
echo "overall coverage: ${total}% (floor ${overall_floor}%)"
fail=0
awk -v t="$total" -v f="$overall_floor" 'BEGIN { exit !(t+0 < f+0) }' && { echo "FAIL: overall below floor"; fail=1; }

for pkg in "$@"; do
  # Per-package statement coverage. With -coverpkg every test binary reports
  # every block, so a block appears once per binary: merge duplicates and
  # count a block as covered if any binary covered it.
  read -r cov stmts < <(awk -v p="/$pkg/" 'NR > 1 && index($1, p) {
      rest = substr($1, index($1, p) + length(p))
      if (index(rest, "/")) next  # direct package only, not subpackages
      n[$1] = $2; if ($3 > 0) hit[$1] = 1
    } END {
      for (b in n) { total += n[b]; if (b in hit) covered += n[b] }
      if (total == 0) print "NA 0"; else printf "%.1f %d\n", covered * 100 / total, total
    }' "$profile")
  if [[ "$cov" == "NA" ]]; then
    echo "critical package $pkg: no statements yet (skipped)"
    continue
  fi
  echo "critical package $pkg: ${cov}% (floor ${critical_floor}%)"
  awk -v t="$cov" -v f="$critical_floor" 'BEGIN { exit !(t+0 < f+0) }' && { echo "FAIL: $pkg below floor"; fail=1; }
done
exit $fail
